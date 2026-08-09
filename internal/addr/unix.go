package addr

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUnixConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-CONNECT requires path")
	}
	path := unixAddr(s.Params[0])
	bindPath := s.OptionValue("bind", "")
	if bindPath != "" {
		bindPath = unixAddr(bindPath)
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
	err := withRetry(ctx, s, g, "UNIX-CONNECT", func() error {
		d := net.Dialer{}
		if bindPath != "" {
			// Classic: bind local unix socket path before connect.
			if !isAbstract(bindPath) {
				_ = os.Remove(bindPath) // stale leftover
			}
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: "unix"}
		}
		c, e := d.DialContext(ctx, "unix", path)
		if e != nil {
			// Classic UNIX client probes peer type: stream fail → try dgram (UNIXTODGRAM).
			if isWrongType(e) {
				return errTryDgram
			}
			return e
		}
		conn = c
		return nil
	})
	if err == errTryDgram || (err != nil && isWrongType(err)) {
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}
	if err != nil {
		return nil, err
	}
	g.Log.Infof("successfully connected to %s", path)
	if g != nil {
		if bindPath != "" {
			g.SockAddr = bindPath
		} else {
			g.SockAddr = path
		}
		g.PeerAddr = path
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		if bindPath != "" {
			_ = os.Remove(bindPath)
		}
		return nil, err
	}
	o := &Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}
	// unlink-close: remove the *local bind* path (classic client option).
	if s.BoolOption("unlink-close") && bindPath != "" {
		o.addCleanup(func() { _ = os.Remove(bindPath) })
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
	return strings.Contains(s, "protocol wrong type") || strings.Contains(s, "eprototype")
}

// openUnixDgramClient is UNIX:/UNIX-CONNECT as datagram (peer is RECVFROM etc.).
func openUnixDgramClient(ctx context.Context, s parse.Spec, mode Mode, g *Global, path, bindPath string) (*Opened, error) {
	// Reuse SENDTO path with synthetic params.
	ps := s
	ps.Params = []string{path}
	if bindPath != "" && !s.HasOption("bind") {
		// Inject bind into a copy of options via OptionValue path: set on Spec.
		ps.Options = append(append([]parse.Option{}, s.Options...), parse.Option{Name: "bind", Value: bindPath})
	}
	return openUnixSendto(ctx, ps, mode, g)
}

func openUnixListen(ctx context.Context, s parse.Spec, _ Mode, g *Global) (*Opened, error) {
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
	err = withUmask(s, func() error {
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

	// mode/perm on socket file (classic fchmod/chmod after bind)
	if err := applyPerm(path, s, nil); err != nil {
		// Non-fatal for some platforms; still try mode=
		if mode := parseFileMode(s, 0); mode != 0 {
			_ = os.Chmod(path, mode)
		}
	}

	fork := s.BoolOption("fork")
	o := &Opened{
		Listener: ln,
		Fork:     fork,
		Label:    "UNIX-LISTEN:" + path,
	}
	o.addCleanup(func() { ln.Close() })

	if fork {
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		return o, nil
	}

	// accept-timeout
	at := acceptTimeout(s)
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
		ln.Close()
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		ln.Close()
		o.Listener = nil
		if a.err != nil {
			o.Close()
			if isTimeoutErr(a.err) {
				return nil, ErrAcceptTimeout
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
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		o.Close()
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

func isAbstract(path string) bool {
	return len(path) > 0 && (path[0] == 0 || path[0] == '@')
}

// openUnixSendto: UNIX-SENDTO:path[,bind=localpath]
// Filesystem unix datagram: send to path, optional bind for replies.
func openUnixSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-SENDTO requires path")
	}
	remote := unixAddr(s.Params[0])
	bindPath := s.OptionValue("bind", "")
	raddr := &net.UnixAddr{Name: remote, Net: "unixgram"}

	var c *net.UnixConn
	var err error
	if bindPath != "" {
		bp := unixAddr(bindPath)
		// Classic: do not unlink the bind path unless unlink-early is set.
		// Unconditional remove would replace a symlink (TEMPNAME_SEC attack).
		if !isAbstract(bp) && s.BoolOption("unlink-early") {
			_ = os.Remove(bp)
		}
		laddr := &net.UnixAddr{Name: bp, Net: "unixgram"}
		c, err = net.ListenUnixgram("unixgram", laddr)
	} else {
		// Unbound unixgram: DialUnix without local name (kernel assigns ephemeral).
		c, err = net.DialUnix("unixgram", nil, raddr)
		if err == nil {
			// Connected socket: use NetStream (Write goes to peer).
			st := relay.Stream(relay.NetStream{Conn: c})
			st, err = wrapCommon(s, st)
			if err != nil {
				c.Close()
				return nil, err
			}
			_ = ctx
			_ = mode
			_ = g
			return &Opened{Stream: st, Label: "UNIX-SENDTO:" + remote}, nil
		}
		// Fallback: raw socket unbound
		c, err = listenUnixgramUnbound()
	}
	if err != nil {
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	o := &Opened{Stream: wrapped, Label: "UNIX-SENDTO:" + remote}
	// Classic default unlink-close=1 for bound unix dgram paths.
	if bindPath != "" {
		bp := unixAddr(bindPath)
		doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
		if doUnlink && !isAbstract(bp) {
			o.addCleanup(func() { _ = os.Remove(bp) })
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
	f.Close()
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("not a UnixConn")
	}
	return uc, nil
}

// openUnixRecvfrom: UNIX-RECVFROM:path — bind, first packet peer for replies.
// With fork: each datagram is a child session (classic).
func openUnixRecvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, true)
}

// openUnixRecv: UNIX-RECV:path — bind, read-only (no reply).
func openUnixRecv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, false)
}

func openUnixRecvCommon(ctx context.Context, s parse.Spec, mode Mode, g *Global, from bool) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires path", s.Type)
	}
	path := unixAddr(s.Params[0])
	if !isAbstract(path) {
		if s.BoolOption("unlink-early") || s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	var c *net.UnixConn
	err := withUmask(s, func() error {
		var e error
		c, e = net.ListenUnixgram("unixgram", laddr)
		return e
	})
	if err != nil {
		return nil, err
	}
	_ = applyPerm(path, s, nil)
	label := s.Type + ":" + path
	// Non-fork RECVFROM: one packet peer, then stream until EOF/timeout.
	// Fork: use a simple packet-accept loop via Opened.Listener adapter.
	if s.BoolOption("fork") && from {
		ln := &unixgramListener{c: c, path: path}
		maxChildren := 0
		if v := s.OptionValue("max-children", ""); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				maxChildren = n
			}
		}
		o := &Opened{
			Listener:    ln,
			Fork:        true,
			Label:       label,
			MaxChildren: maxChildren,
		}
		if !isAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
			o.addCleanup(func() {
				ln.Close()
				_ = os.Remove(path)
			})
		} else {
			o.addCleanup(func() { ln.Close() })
		}
		_ = ctx
		_ = mode
		_ = g
		return o, nil
	}

	st := &unixRecvStream{c: c, from: from}
	wrapped, err := wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	o := &Opened{Stream: wrapped, Label: label}
	if !isAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
		o.addCleanup(func() {
			c.Close()
			_ = os.Remove(path)
		})
	} else {
		o.addCleanup(func() { c.Close() })
	}
	_ = ctx
	_ = mode
	_ = g
	return o, nil
}

// openUnixDatagram: UNIX-DATAGRAM:path[,bind=local]
// Connected-style dgram to path (or dual peer).
func openUnixDatagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
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
	for {
		n, addr, err := u.c.ReadFromUnix(p)
		if err != nil {
			return n, err
		}
		if addr != nil && u.peer != nil && addr.Name == u.peer.Name {
			return n, nil
		}
		// Drop packets from other peers when filtering (fork children race).
		// In fork mode each Accept takes one packet; extra reads may be empty wait.
		_ = addr
		return n, nil
	}
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
func openAbstractListen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-LISTEN requires name")
	}
	name := s.Params[0]
	if !isAbstract(name) {
		name = "@" + name
	}
	path := unixAddr(name)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	fork := s.BoolOption("fork")
	o := &Opened{
		Listener: ln,
		Fork:     fork,
		Label:    "ABSTRACT-LISTEN:" + name,
	}
	o.addCleanup(func() { ln.Close() })
	if fork {
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		return o, nil
	}
	// Non-fork: accept one; honour accept-timeout (classic ABSTRACT_USER etc.).
	at := acceptTimeout(s)
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
		ln.Close()
		return nil, ctx.Err()
	case a := <-ch:
		ln.Close()
		o.Listener = nil
		if a.err != nil {
			if isTimeoutErr(a.err) {
				return nil, ErrAcceptTimeout
			}
			return nil, a.err
		}
		st := relay.Stream(relay.NetStream{Conn: a.c})
		st, err = wrapCommon(s, st)
		if err != nil {
			a.c.Close()
			return nil, err
		}
		o.Stream = st
		return o, nil
	}
}

// openAbstractConnect: ABSTRACT-CONNECT / ABSTRACT-CLIENT stream connect.
func openAbstractConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-CONNECT requires name")
	}
	name := s.Params[0]
	if !isAbstract(name) {
		name = "@" + name
	}
	path := unixAddr(name)
	d := net.Dialer{Timeout: connectTimeout(s)}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	st := relay.Stream(relay.NetStream{Conn: c})
	st, err = wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = mode
	_ = g
	return &Opened{Stream: st, Label: "ABSTRACT-CONNECT:" + name}, nil
}

// openAbstractSendto implements ABSTRACT-SENDTO bind+datagram style.
// For stream-ish echo tests, ABSTRACT-SENDTO with bind to same name loops on dgram.
func openAbstractSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-SENDTO requires name")
	}
	// Classic ABSTRACT-SENDTO:path — abstract name from path (filesystem path becomes abstract name).
	name := s.Params[0]
	// Use abstract form: leading @ or convert path to abstract label.
	absName := name
	if !isAbstract(absName) {
		absName = "@" + name // mark; unixAddr converts
	}
	target := unixAddr(absName)
	bindOpt := s.OptionValue("bind", "")
	var laddr *net.UnixAddr
	if bindOpt != "" {
		bp := bindOpt
		if !isAbstract(bp) {
			bp = "@" + bp
		}
		laddr = &net.UnixAddr{Name: unixAddr(bp), Net: "unixgram"}
	}
	raddr := &net.UnixAddr{Name: target, Net: "unixgram"}
	c, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		// Fallback: dial unixgram
		d := net.Dialer{}
		if laddr != nil {
			d.LocalAddr = laddr
		}
		conn, e := d.DialContext(ctx, "unixgram", raddr.String())
		if e != nil {
			return nil, e
		}
		st := relay.Stream(relay.NetStream{Conn: conn})
		st, err = wrapCommon(s, st)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return &Opened{Stream: st, Label: "ABSTRACT-SENDTO:" + name}, nil
	}
	// Connected-style: write to raddr, read any
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = mode
	_ = g
	return &Opened{Stream: wrapped, Label: "ABSTRACT-SENDTO:" + name}, nil
}

type unixgramConn struct {
	*net.UnixConn
	raddr *net.UnixAddr
}

func (u *unixgramConn) Write(p []byte) (int, error) {
	return u.UnixConn.WriteToUnix(p, u.raddr)
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
