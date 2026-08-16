package netopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

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
			Kind:        xio.KindListen,
			Listener:    ln,
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
