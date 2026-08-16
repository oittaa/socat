package netopen

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

const unixTempChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// resolveUnixBind returns bind= or a unique unix-bind-tempname path (classic).
func resolveUnixBind(s parse.Spec) (string, error) {
	hasTemp := s.HasOption("unix-bind-tempname")
	hasBind := s.HasOption("bind")
	if hasTemp && hasBind {
		return "", fmt.Errorf("do not use both options bind and unix-bind-tempname")
	}
	if !hasTemp {
		return s.OptionValue("bind", ""), nil
	}
	o, _ := s.OptionNamed("unix-bind-tempname")
	pat := ""
	if o.Has && o.Value != "" && o.Value != "1" {
		pat = o.Value
	}
	return unixTempnam(pat)
}

// unixTempnam fills XXXXXX like classic xio_tempnam / tempnam(3).
func unixTempnam(pattern string) (string, error) {
	if pattern == "" {
		pattern = "/tmp/socat-bind.XXXXXX"
	}
	idx := strings.LastIndex(pattern, "XXXXXX")
	if idx < 0 {
		return "", fmt.Errorf("unix-bind-tempname: path pattern is not valid")
	}
	abs := xio.IsAbstract(unixAddr(pattern))
	var b [6]byte
	for n := 0; n < 10000; n++ {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		var out [6]byte
		for i := 0; i < 6; i++ {
			out[i] = unixTempChars[int(b[i])%len(unixTempChars)]
		}
		name := pattern[:idx] + string(out[:]) + pattern[idx+6:]
		if abs {
			return name, nil
		}
		if _, err := os.Lstat(unixAddr(name)); os.IsNotExist(err) {
			return name, nil
		}
	}
	return "", fmt.Errorf("unix-bind-tempname: no free name")
}

func openUnixConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-CONNECT requires path")
	}
	path := unixAddr(s.Params[0])
	bindPath, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	if bindPath != "" {
		if strings.HasPrefix(strings.ToUpper(s.Type), "ABSTRACT") {
			bindPath = abstractName(bindPath)
		} else {
			bindPath = unixAddr(bindPath)
		}
	}

	// Explicit socktype=2 (SOCK_DGRAM) or classic client fallback when peer is dgram.
	wantDgram := false
	if v := s.OptionValue("socktype", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n == syscall.SOCK_DGRAM {
			wantDgram = true
		}
	}

	if wantDgram {
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}

	var conn net.Conn
	// If stream dial with LocalAddr fails (e.g. peer is SOCK_DGRAM), the kernel
	// may have already bound the local path — remove it before dgram fallback
	// (UNIXTODGRAM: classic probes stream then dgram with the same bind= path).
	cleanupStreamBind := func() {
		if bindPath != "" && !xio.IsAbstract(bindPath) {
			_ = os.Remove(bindPath)
		}
	}
	err = xio.WithRetry(ctx, s, g, "UNIX-CONNECT", func() error {
		d := net.Dialer{}
		if bindPath != "" {
			// Classic client bind path: remove stale leftover before bind.
			if !xio.IsAbstract(bindPath) {
				_ = os.Remove(bindPath)
			}
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: "unix"}
		}
		c, e := d.DialContext(ctx, "unix", path)
		if e != nil {
			// Classic UNIX client probes peer type: stream fail → try dgram (UNIXTODGRAM).
			if isWrongType(e) {
				cleanupStreamBind()
				return errTryDgram
			}
			// connection refused / not a socket can also mean dgram peer exists
			if isConnRefusedOrNotSocket(e) && bindPath != "" {
				cleanupStreamBind()
				return errTryDgram
			}
			return e
		}
		conn = c
		return nil
	})
	if err == errTryDgram || (err != nil && isWrongType(err)) {
		cleanupStreamBind()
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}
	if err != nil {
		return nil, err
	}
	if g != nil && g.Log != nil {
		g.Log.Infof("successfully connected to %s", path)
	}
	if g != nil {
		if bindPath != "" {
			g.SockAddr = bindPath
		} else {
			g.SockAddr = path
		}
		g.PeerAddr = path
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		if bindPath != "" {
			_ = os.Remove(bindPath)
		}
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}
	// unlink-close: remove the *local bind* path (classic client option).
	if s.BoolOption("unlink-close") && bindPath != "" {
		o.AddCleanup(func() { _ = os.Remove(bindPath) })
	}
	return o, nil
}

// errTryDgram signals stream connect hit EPROTOTYPE; fall back to unixgram.
var errTryDgram = fmt.Errorf("try unixgram")

func isWrongType(err error) bool {
	if err == nil {
		return false
	}
	if err == syscall.EPROTOTYPE {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "protocol wrong type") || strings.Contains(s, "eprototype") ||
		strings.Contains(s, "wrong protocol type")
}

func isConnRefusedOrNotSocket(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "not a socket") ||
		strings.Contains(s, "socket operation on non-socket")
}

// openUnixDgramClient is UNIX:/UNIX-CONNECT as datagram (peer is RECVFROM etc.).
func openUnixDgramClient(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, path, bindPath string) (*xio.Opened, error) {
	// Reuse SENDTO path with synthetic params.
	ps := s
	ps.Params = []string{path}
	if bindPath != "" {
		var opts []parse.Option
		for _, o := range s.Options {
			if o.Name == "unix-bind-tempname" {
				continue
			}
			opts = append(opts, o)
		}
		if !s.HasOption("bind") {
			opts = append(opts, parse.Option{Name: "bind", Value: bindPath, Has: true})
		}
		ps.Options = opts
	}
	return openUnixSendto(ctx, ps, mode, g)
}

func openUnixListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		// Fail fast: classic testaddrs uses UNIX-LISTEN::::: probes.
		return nil, fmt.Errorf("UNIX-LISTEN requires path")
	}
	path := s.Params[0]

	if s.BoolOption("unlink-early") {
		_ = os.Remove(path)
	} else if _, err := os.Stat(path); err == nil {
		// classic may fail if exists; try remove if reuseaddr
		if s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}

	lc := net.ListenConfig{}
	var ln net.Listener
	var err error
	err = xio.WithUmask(s, func() error {
		var e error
		ln, e = lc.Listen(ctx, "unix", path)
		return e
	})
	if err != nil {
		return nil, err
	}

	// Go's UnixListener unlinks the path on Close by default. Match classic
	// unlink-close: default true; unlink-close=0 keeps the filesystem entry.
	doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(doUnlink)
	}

	// mode/perm/user on socket file (classic fchmod/fchown after bind)
	if err := xio.ApplyPerm(path, s, nil); err != nil {
		// Non-fatal for some platforms; still try mode=
		if mode := xio.ParseFileMode(s, 0); mode != 0 {
			_ = os.Chmod(path, mode)
		}
	}
	_ = xio.ApplyOwner(path, s, nil)

	// Classic: bind= on UNIX-LISTEN is invalid (must not bind twice / INTERNAL).
	// UNIX_L_BIND expects a non-zero exit without the word INTERNAL.
	if s.HasOption("bind") {
		return nil, fmt.Errorf("option \"bind\" with UNIX-LISTEN is not supported")
	}

	// Ensure path is removed on SIGTERM (SetUnlinkOnClose only runs on Close).
	if doUnlink && !xio.IsAbstract(path) {
		xio.RegisterUnlinkPath(path)
	}

	fork := s.BoolOption("fork")
	o := &xio.Opened{
		Listener: ln,
		Fork:     fork,
		Label:    "UNIX-LISTEN:" + path,
	}
	o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned

	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}()
		return o, nil
	}

	// accept-timeout
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	} else if v := s.OptionValue("accept-timeout", ""); v != "" {
		if f, e := strconv.ParseFloat(v, 64); e == nil && f > 0 {
			deadline = time.Now().Add(time.Duration(f * float64(time.Second)))
		}
	}
	g.Log.Noticef("listening on %s", path)
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	var conn net.Conn
	select {
	case <-ctx.Done():
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		o.Listener = nil
		if a.err != nil {
			_ = o.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			if xio.IsTimeoutErr(a.err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, a.err
		}
		conn = a.c
	}
	// UNIX env: sock = listen path; peer = client path if bound.
	if g != nil {
		g.SockAddr = path
		g.SockPort = ""
		g.PeerPort = ""
		if ra := conn.RemoteAddr(); ra != nil {
			if ua, ok := ra.(*net.UnixAddr); ok && ua.Name != "" {
				g.PeerAddr = ua.Name
			} else if s := ra.String(); s != "" {
				g.PeerAddr = s
			} else {
				g.PeerAddr = path
			}
		} else {
			g.PeerAddr = path
		}
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		_ = o.Close()    // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o.Stream = st
	return o, nil
}

// abstract unix (Linux): classic ABSTRACT-* and @path / \0path forms.
// Go net uses a leading NUL byte for abstract namespace names.
func unixAddr(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '@' {
		return string(byte(0)) + path[1:]
	}
	// Already abstract (NUL-prefixed)
	if path[0] == 0 {
		return path
	}
	return path
}

func openUnixSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-SENDTO requires path")
	}
	remote := unixAddr(s.Params[0])
	bindPath, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	raddr := &net.UnixAddr{Name: remote, Net: "unixgram"}

	var c *net.UnixConn
	if bindPath != "" {
		bp := unixAddr(bindPath)
		// Client bind for SENDTO / UNIX dgram: remove stale path (classic creates
		// a fresh local name). Do not follow a symlink target (TEMPNAME_SEC):
		// if bp is a symlink, Leave it and let bind fail with EADDRINUSE.
		if !xio.IsAbstract(bp) {
			if fi, e := os.Lstat(bp); e == nil && fi.Mode()&os.ModeSymlink == 0 {
				_ = os.Remove(bp)
			} else if os.IsNotExist(e) {
				// ok
			} else if e == nil && fi.Mode()&os.ModeSymlink != 0 {
				// symlink: do not remove (security); bind will fail
			} else if s.BoolOption("unlink-early") {
				_ = os.Remove(bp)
			}
		}
		laddr := &net.UnixAddr{Name: bp, Net: "unixgram"}
		c, err = net.ListenUnixgram("unixgram", laddr)
	} else {
		// Unbound unixgram: DialUnix without local name (kernel assigns ephemeral).
		c, err = net.DialUnix("unixgram", nil, raddr)
		if err == nil {
			// Connected socket: use NetStream (Write goes to peer).
			st := relay.Stream(relay.NetStream{Conn: c})
			st, err = xio.WrapCommon(s, st)
			if err != nil {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return nil, err
			}
			_ = ctx
			_ = mode
			_ = g
			return &xio.Opened{Stream: st, Label: "UNIX-SENDTO:" + remote}, nil
		}
		// Fallback: raw socket unbound
		c, err = listenUnixgramUnbound()
	}
	if err != nil {
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o := &xio.Opened{Stream: wrapped, Label: "UNIX-SENDTO:" + remote}
	// Classic default unlink-close=1 for bound unix dgram paths.
	if bindPath != "" {
		bp := unixAddr(bindPath)
		doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
		if doUnlink && !xio.IsAbstract(bp) {
			o.AddCleanup(func() { _ = os.Remove(bp) })
		}
	}
	_ = ctx
	_ = mode
	_ = g
	return o, nil
}

// listenUnixgramUnbound creates an unbound AF_UNIX SOCK_DGRAM socket.
func listenUnixgramUnbound() (*net.UnixConn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "unixgram-unbound")
	c, err := net.FilePacketConn(f)
	_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	if err != nil {
		_ = syscall.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, fmt.Errorf("not a UnixConn")
	}
	return uc, nil
}

// openUnixRecvfrom: UNIX-RECVFROM:path — bind, first packet peer for replies.
// With fork: each datagram is a child session (classic).
func openUnixRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, true)
}

// openUnixRecv: UNIX-RECV:path — bind, read-only (no reply).
func openUnixRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, false)
}

func openUnixRecvCommon(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, from bool) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires path", s.Type)
	}
	path := unixAddr(s.Params[0])
	if !xio.IsAbstract(path) {
		if s.BoolOption("unlink-early") || s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	var c *net.UnixConn
	err := xio.WithUmask(s, func() error {
		var e error
		c, e = net.ListenUnixgram("unixgram", laddr)
		return e
	})
	if err != nil {
		return nil, err
	}
	_ = xio.ApplyPerm(path, s, nil)
	label := s.Type + ":" + path
	// Non-fork RECVFROM: one packet peer, then stream until EOF/timeout.
	// Fork: use a simple packet-accept loop via xio.Opened.Listener adapter.
	if s.BoolOption("fork") && from {
		ln := &unixgramListener{c: c, path: path}
		maxChildren := 0
		if v := s.OptionValue("max-children", ""); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				maxChildren = n
			}
		}
		o := &xio.Opened{
			Listener:    ln,
			Fork:        true,
			Label:       label,
			MaxChildren: maxChildren,
		}
		if !xio.IsAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
			xio.RegisterUnlinkPath(path)
			o.AddCleanup(func() {
				_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				_ = os.Remove(path)
			})
		} else {
			o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned
		}
		_ = xio.ApplyOwner(path, s, nil)
		_ = ctx
		_ = mode
		_ = g
		return o, nil
	}

	st := &unixRecvStream{c: c, from: from}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o := &xio.Opened{Stream: wrapped, Label: label}
	_ = xio.ApplyOwner(path, s, nil)
	if !xio.IsAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
		xio.RegisterUnlinkPath(path)
		o.AddCleanup(func() {
			_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			_ = os.Remove(path)
		})
	} else {
		o.AddCleanup(func() { _ = c.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned
	}
	_ = ctx
	_ = mode
	_ = g
	return o, nil
}

// openUnixDatagram: UNIX-DATAGRAM:path[,bind=local]
// Connected-style dgram to path (or dual peer).
func openUnixDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Same as sendto for basic echo tests.
	return openUnixSendto(ctx, s, mode, g)
}

// unixRecvStream: first Recvfrom captures peer when from=true; Write replies to peer.
// Classic non-fork RECVFROM: after the first datagram is delivered, further
// Read returns EOF so one-shot echo servers (RECVFROM PIPE) exit.
type unixRecvStream struct {
	c        *net.UnixConn
	from     bool
	peer     *net.UnixAddr
	got      bool
	firstEOF bool // after first packet fully delivered
}

func (u *unixRecvStream) Read(p []byte) (int, error) {
	if u.from && u.firstEOF {
		return 0, io.EOF
	}
	n, addr, err := u.c.ReadFromUnix(p)
	if err != nil {
		return n, err
	}
	if u.from && !u.got && addr != nil {
		u.peer = addr
		u.got = true
		// One-shot: next Read is EOF after this payload is returned.
		u.firstEOF = true
	}
	return n, nil
}
func (u *unixRecvStream) Write(p []byte) (int, error) {
	if !u.from || u.peer == nil {
		return 0, fmt.Errorf("UNIX-RECV is read-only")
	}
	return u.c.WriteToUnix(p, u.peer)
}
func (u *unixRecvStream) Close() error         { return u.c.Close() }
func (u *unixRecvStream) ShutdownWrite() error { return nil }
func (u *unixRecvStream) SetReadDeadline(t time.Time) error {
	return u.c.SetReadDeadline(t)
}

// unixgramListener turns RECVFROM,fork into accept-like sessions per packet.
type unixgramListener struct {
	c    *net.UnixConn
	path string
}

func (l *unixgramListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65536)
	n, addr, err := l.c.ReadFromUnix(buf)
	if err != nil {
		return nil, err
	}
	// Return a connected-style unixgram session for this peer with first data.
	return &unixPacketConn{
		c:     l.c,
		peer:  addr,
		first: append([]byte(nil), buf[:n]...),
		// Do not close shared parent socket on child Close.
		shared: true,
	}, nil
}
func (l *unixgramListener) Close() error {
	return l.c.Close()
}
func (l *unixgramListener) Addr() net.Addr {
	return &net.UnixAddr{Name: l.path, Net: "unixgram"}
}

// unixPacketConn is one datagram session (first payload + reply path).
type unixPacketConn struct {
	c      *net.UnixConn
	peer   *net.UnixAddr
	first  []byte
	shared bool
	closed bool
}

func (u *unixPacketConn) Read(p []byte) (int, error) {
	if len(u.first) > 0 {
		n := copy(p, u.first)
		u.first = u.first[n:]
		if len(u.first) == 0 {
			u.first = nil
		}
		return n, nil
	}
	// Subsequent reads from same peer only.
	n, addr, err := u.c.ReadFromUnix(p)
	if err != nil {
		return n, err
	}
	if addr != nil && u.peer != nil && addr.Name != u.peer.Name {
		// Other-peer packets are dropped by the caller / next Accept in fork mode.
		_ = addr
	}
	return n, nil
}
func (u *unixPacketConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, fmt.Errorf("no peer")
	}
	return u.c.WriteToUnix(p, u.peer)
}
func (u *unixPacketConn) Close() error {
	if u.closed {
		return nil
	}
	u.closed = true
	if u.shared {
		return nil
	}
	return u.c.Close()
}
func (u *unixPacketConn) LocalAddr() net.Addr  { return u.c.LocalAddr() }
func (u *unixPacketConn) RemoteAddr() net.Addr { return u.peer }
func (u *unixPacketConn) SetDeadline(t time.Time) error {
	return u.c.SetDeadline(t)
}
func (u *unixPacketConn) SetReadDeadline(t time.Time) error {
	return u.c.SetReadDeadline(t)
}
func (u *unixPacketConn) SetWriteDeadline(t time.Time) error {
	return u.c.SetWriteDeadline(t)
}

// openAbstractListen: ABSTRACT-LISTEN:name — stream listen in Linux abstract namespace.
func openAbstractListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-LISTEN requires name")
	}
	name := s.Params[0]
	if !xio.IsAbstract(name) {
		name = "@" + name
	}
	path := unixAddr(name)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	fork := s.BoolOption("fork")
	o := &xio.Opened{
		Listener: ln,
		Fork:     fork,
		Label:    "ABSTRACT-LISTEN:" + name,
	}
	o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned
	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}()
		return o, nil
	}
	// Non-fork: accept one; honour accept-timeout (classic ABSTRACT_USER etc.).
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	select {
	case <-ctx.Done():
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, ctx.Err()
	case a := <-ch:
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		o.Listener = nil
		if a.err != nil {
			if xio.IsTimeoutErr(a.err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, a.err
		}
		st := relay.Stream(relay.NetStream{Conn: a.c})
		st, err = xio.WrapCommon(s, st)
		if err != nil {
			_ = a.c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
		o.Stream = st
		return o, nil
	}
}

// openAbstractConnect: ABSTRACT-CONNECT / ABSTRACT-CLIENT stream connect.
func openAbstractConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-CONNECT requires name")
	}
	name := s.Params[0]
	if !xio.IsAbstract(name) {
		name = "@" + name
	}
	ps := s
	ps.Params = []string{name}
	return openUnixConnect(ctx, ps, mode, g)
}

// abstractName maps classic ABSTRACT-*:path (even if path is a filesystem path
// that was touch'ed so non-abstract would fail) to the abstract namespace name.
func abstractName(raw string) string {
	if xio.IsAbstract(raw) {
		return unixAddr(raw)
	}
	// Classic: ABSTRACT-RECVFROM:/tmp/foo uses abstract name equal to the string
	// (with leading NUL), not a filesystem socket.
	return "\x00" + raw
}

// openAbstractRecvfrom: bind abstract datagram, one peer packet then reply (like UNIX-RECVFROM).
func openAbstractRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-RECVFROM requires name")
	}
	path := abstractName(s.Params[0])
	ps := s
	ps.Params = []string{path}
	// Force abstract path through openUnixRecvCommon without filesystem unlink.
	return openUnixRecvCommon(ctx, ps, mode, g, true)
}

// openAbstractRecv: bind abstract datagram, read-only merge of packets.
func openAbstractRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-RECV requires name")
	}
	path := abstractName(s.Params[0])
	ps := s
	ps.Params = []string{path}
	return openUnixRecvCommon(ctx, ps, mode, g, false)
}

// openAbstractSendto implements ABSTRACT-SENDTO[,bind=] datagram send.
func openAbstractSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-SENDTO requires name")
	}
	target := abstractName(s.Params[0])
	bindOpt, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	var laddr *net.UnixAddr
	if bindOpt != "" {
		laddr = &net.UnixAddr{Name: abstractName(bindOpt), Net: "unixgram"}
	}
	raddr := &net.UnixAddr{Name: target, Net: "unixgram"}
	// Prefer bind local abstract name then WriteTo (classic client with bind=).
	var c *net.UnixConn
	if laddr != nil {
		c, err = net.ListenUnixgram("unixgram", laddr)
		if err != nil {
			return nil, err
		}
	} else {
		// Unbound abstract sendto: create unbound unixgram.
		c, err = listenUnixgramUnbound()
		if err != nil {
			return nil, err
		}
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: wrapped, Label: "ABSTRACT-SENDTO:" + s.Params[0]}, nil
}

type unixgramConn struct {
	*net.UnixConn
	raddr *net.UnixAddr
}

func (u *unixgramConn) Write(p []byte) (int, error) {
	return u.WriteToUnix(p, u.raddr)
}
func (u *unixgramConn) ShutdownWrite() error { return nil }
func (u *unixgramConn) SetReadDeadline(t time.Time) error {
	return u.UnixConn.SetReadDeadline(t)
}
func (u *unixgramConn) SetDeadline(t time.Time) error {
	return u.UnixConn.SetDeadline(t)
}

// silence unused on non-special builds
var _ = syscall.AF_UNIX
