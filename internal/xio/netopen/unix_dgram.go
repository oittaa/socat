package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
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
			if err := applyUnixgramSocketOptions(c, s); err != nil {
				logx.CloseQuiet(c)
				return nil, err
			}
			// Connected socket: use NetStream (Write goes to peer).
			st := relay.Stream(relay.NetStream{Conn: c})
			st, err = xio.WrapCommon(s, st)
			if err != nil {
				logx.CloseQuiet(c)
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
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(c)
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
	logx.CloseQuiet(f)
	if err != nil {
		logx.CloseErr(syscall.Close(fd))
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		logx.CloseQuiet(c)
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
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		logx.CloseQuiet(c)
		if !xio.IsAbstract(path) {
			_ = os.Remove(path)
		}
		return nil, err
	}
	if err := xio.ApplyPerm(path, s, nil); err != nil {
		_ = c.Close()
		if !xio.IsAbstract(path) {
			_ = os.Remove(path)
		}
		return nil, err
	}
	if err := xio.ApplyOwner(path, s, nil); err != nil {
		_ = c.Close()
		if !xio.IsAbstract(path) {
			_ = os.Remove(path)
		}
		return nil, err
	}
	label := s.Type + ":" + path
	if s.BoolOption("fork") && from {
		ln := &unixgramListener{c: c, path: path, spec: s, g: g, ctx: ctx}
		d, terr := xio.RecvTimeoutFromSpec(s)
		if terr != nil {
			logx.CloseQuiet(ln)
			return nil, terr
		}
		ln.rcvTimeout = d
		_, maxChildren, ferr := xio.ForkLimits(s)
		if ferr != nil {
			logx.CloseQuiet(ln)
			return nil, ferr
		}
		o := &xio.Opened{
			Kind:        xio.KindListen,
			Listener:    ln,
			Label:       label,
			MaxChildren: maxChildren,
			WrapDial: func(conn net.Conn) (relay.Stream, error) {
				return xio.WrapCommon(s, relay.NetStream{Conn: conn})
			},
		}
		if !xio.IsAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
			unregister := xio.RegisterUnlinkPath(path)
			o.AddCleanup(func() {
				unregister()
				logx.CloseQuiet(ln)
				_ = os.Remove(path)
			})
		} else {
			o.AddCleanup(func() { logx.CloseQuiet(ln) })
		}
		_ = mode
		return o, nil
	}

	if from {
		first, peer, err := waitUnixRecvfromPacket(ctx, c, g)
		if err != nil {
			logx.CloseQuiet(c)
			if !xio.IsAbstract(path) {
				_ = os.Remove(path)
			}
			return nil, err
		}
		st := relay.Stream(&unixRecvStream{c: c, from: true, peer: peer, first: first, firstEOF: true})
		wrapped, err := xio.WrapCommon(s, st)
		if err != nil {
			logx.CloseQuiet(c)
			return nil, err
		}
		o := &xio.Opened{Stream: wrapped, Label: label}
		if !xio.IsAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
			unregister := xio.RegisterUnlinkPath(path)
			o.AddCleanup(func() {
				unregister()
				logx.CloseQuiet(c)
				_ = os.Remove(path)
			})
		} else {
			o.AddCleanup(func() { logx.CloseQuiet(c) })
		}
		_ = mode
		return o, nil
	}

	st := &unixRecvStream{c: c, from: from}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	o := &xio.Opened{Stream: wrapped, Label: label}
	if !xio.IsAbstract(path) && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close")) {
		unregister := xio.RegisterUnlinkPath(path)
		o.AddCleanup(func() {
			unregister()
			logx.CloseQuiet(c)
			_ = os.Remove(path)
		})
	} else {
		o.AddCleanup(func() { logx.CloseQuiet(c) })
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

func waitUnixRecvfromPacket(ctx context.Context, c *net.UnixConn, g *xio.Global) ([]byte, *net.UnixAddr, error) {
	buf := make([]byte, 65536)
	n, _, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UnixAddr, error) {
		nn, a, e := c.ReadFromUnix(buf)
		return nn, nil, a, e
	})
	if err != nil {
		return nil, nil, err
	}
	if g != nil && addr != nil {
		if addr.Name != "" {
			g.PeerAddr = addr.Name
		} else {
			g.PeerAddr = addr.String()
		}
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

// unixRecvStream: first Recvfrom captures peer when from=true; Write replies to peer.
// Classic non-fork RECVFROM: after the first datagram is delivered, further
// Read returns EOF so one-shot echo servers (RECVFROM PIPE) exit.
type unixRecvStream struct {
	c        *net.UnixConn
	from     bool
	peer     *net.UnixAddr
	first    []byte
	firstEOF bool
}

func (u *unixRecvStream) Read(p []byte) (int, error) {
	if len(u.first) > 0 {
		n := copy(p, u.first)
		u.first = nil
		return n, nil
	}
	if u.from && u.firstEOF {
		return 0, io.EOF
	}
	n, addr, err := u.c.ReadFromUnix(p)
	if err != nil {
		return n, err
	}
	if u.from && addr != nil {
		u.peer = addr
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
	c          *net.UnixConn
	path       string
	spec       parse.Spec
	g          *xio.Global
	ctx        context.Context
	rcvTimeout time.Duration
	writeMu    sync.Mutex
}

func (l *unixgramListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65536)
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if l.rcvTimeout > 0 {
			_ = l.c.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		n, _, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UnixAddr, error) {
			nn, a, e := l.c.ReadFromUnix(buf)
			return nn, nil, a, e
		})
		if err != nil {
			if l.ctx != nil && l.ctx.Err() != nil {
				return nil, err
			}
			if l.rcvTimeout > 0 && xio.IsTimeoutErr(err) {
				continue
			}
			return nil, err
		}
		return &unixPacketConn{
			c:       l.c,
			peer:    addr,
			first:   append([]byte(nil), buf[:n]...),
			shared:  true,
			writeMu: &l.writeMu,
		}, nil
	}
}
func (l *unixgramListener) Close() error {
	return l.c.Close()
}
func (l *unixgramListener) Addr() net.Addr {
	return &net.UnixAddr{Name: l.path, Net: "unixgram"}
}

// unixPacketConn is one datagram session (first payload + reply path).
type unixPacketConn struct {
	c             *net.UnixConn
	peer          *net.UnixAddr
	first         []byte
	shared        bool
	closed        bool
	writeMu       *sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func (u *unixPacketConn) Read(p []byte) (int, error) {
	if len(u.first) > 0 {
		n := copy(p, u.first)
		u.first = nil
		return n, nil
	}
	// Classic UNIX-RECVFROM,fork is one-shot (XIODATA_RECVFROM_ONE): the
	// accepted datagram is already in first. Never read the shared parent
	// socket again — that would steal other peers' packets.
	return 0, io.EOF
}
func (u *unixPacketConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, fmt.Errorf("no peer")
	}
	if u.writeMu != nil {
		u.writeMu.Lock()
		defer u.writeMu.Unlock()
	}
	u.deadlineMu.Lock()
	deadline := u.writeDeadline
	u.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
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
	return u.SetWriteDeadline(t)
}
func (u *unixPacketConn) SetReadDeadline(time.Time) error {
	// Read never touches the shared listener; do not install a deadline on it.
	return nil
}
func (u *unixPacketConn) SetWriteDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	u.writeDeadline = t
	u.deadlineMu.Unlock()
	return nil
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
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: wrapped, Label: "ABSTRACT-SENDTO:" + s.Params[0]}, nil
}

func applyUnixgramSocketOptions(c *net.UnixConn, s parse.Spec) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = xio.ApplySocketOptions(int(fd), s)
	})
	return errors.Join(controlErr, optionErr)
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
