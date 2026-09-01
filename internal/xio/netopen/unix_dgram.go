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
	return openUnixgramSend(ctx, s, mode, g, true)
}

func openUnixDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixgramSend(ctx, s, mode, g, false)
}

func openUnixgramSend(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, filterPeer bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires path", s.Type)
	}
	remote := unixAddr(s.Params[0])
	bindPath, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	raddr := &net.UnixAddr{Name: remote, Net: "unixgram"}

	var c *net.UnixConn
	bound := ""
	if bindPath != "" {
		bound = unixAddr(bindPath)
		if err := prepareUnixClientBind(bound, s); err != nil {
			return nil, err
		}
		laddr := &net.UnixAddr{Name: bound, Net: "unixgram"}
		c, err = listenUnixgramBound(s, laddr, false)
	} else {
		c, err = listenUnixgramUnbound(s)
	}
	if err != nil {
		return nil, err
	}
	life := trackUnixBind(bound, s)
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		life.drop(c)
		return nil, err
	}
	if err := xio.ApplyNamedAfterBind(bound, s, nil); err != nil {
		life.drop(c)
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr, filterPeer: filterPeer, ctx: ctx}
	wrapped, err := xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	o := &xio.Opened{Stream: wrapped, Label: s.Type + ":" + remote}
	life.attach(o)
	_ = mode
	_ = g
	return o, nil
}

// listenUnixgramUnbound creates an unbound AF_UNIX SOCK_DGRAM socket and
// applies after-socket then before-bind options.
func listenUnixgramUnbound(s parse.Spec) (*net.UnixConn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	// syscall.Socket returns int on Unix and syscall.Handle (uintptr) on Windows.
	if err := xio.ApplyPastSocketThenPrebind(int(fd), s, "unixgram"); err != nil {
		logx.CloseErr(syscall.Close(fd))
		return nil, err
	}
	return unixConnFromFD(uintptr(fd), "unixgram-unbound")
}

func listenUnixgramBound(s parse.Spec, laddr *net.UnixAddr, applyUmask bool) (*net.UnixConn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyPastSocketThenPrebind(int(fd), s, "unixgram"); err != nil {
		logx.CloseErr(syscall.Close(fd))
		return nil, err
	}
	bind := func() error {
		return bindUnixPath(int(fd), laddr.Name, unixTightSocklen(s))
	}
	if applyUmask {
		err = xio.WithUmask(s, bind)
	} else {
		err = bind()
	}
	if err != nil {
		logx.CloseErr(syscall.Close(fd))
		return nil, err
	}
	return unixConnFromFD(uintptr(fd), "unixgram")
}

func unixConnFromFD(fd uintptr, name string) (*net.UnixConn, error) {
	f := os.NewFile(fd, name)
	if f == nil {
		return nil, fmt.Errorf("invalid socket fd")
	}
	c, err := net.FilePacketConn(f)
	// NewFile owns fd; FilePacketConn dups it. Close the original either way.
	logx.CloseQuiet(f)
	if err != nil {
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
// With fork: each datagram is a child session.
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
	if !from && mode == xio.ModeWrite {
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	path := unixAddr(s.Params[0])
	if err := prepareUnixFilesystemPath(path, s); err != nil {
		return nil, err
	}
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	c, err := listenUnixgramBound(s, laddr, true)
	if err != nil {
		return nil, err
	}
	life := trackUnixBind(path, s)
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		life.drop(c)
		return nil, err
	}
	if err := xio.ApplyNamedAfterBind(path, s, nil); err != nil {
		life.drop(c)
		return nil, err
	}
	label := s.Type + ":" + path
	if s.BoolOption("fork") && from {
		ln := &unixgramListener{c: c, path: path, spec: s, g: g, ctx: ctx}
		d, terr := xio.RecvTimeoutFromSpec(s)
		if terr != nil {
			life.drop(ln)
			return nil, terr
		}
		ln.rcvTimeout = d
		_, maxChildren, ferr := xio.ForkLimits(s)
		if ferr != nil {
			life.drop(ln)
			return nil, ferr
		}
		o := &xio.Opened{
			Kind:        xio.KindListen,
			Listener:    ln,
			Label:       label,
			MaxChildren: maxChildren,
			WrapDial: func(conn net.Conn) (relay.Stream, error) {
				return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: conn})
			},
		}
		life.attach(o)
		_ = mode
		return o, nil
	}

	if from {
		first, peer, err := waitUnixRecvfromPacket(ctx, c, g)
		if err != nil {
			life.drop(c)
			return nil, err
		}
		st := relay.Stream(&unixRecvStream{c: c, from: true, peer: peer, first: first, firstEOF: true})
		wrapped, err := xio.WrapCommonAfterConnected(s, st)
		if err != nil {
			life.drop(c)
			return nil, err
		}
		o := &xio.Opened{Stream: wrapped, Label: label}
		life.attach(o)
		_ = mode
		return o, nil
	}

	st := &unixRecvStream{c: c, from: from}
	wrapped, err := xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	o := &xio.Opened{Stream: wrapped, Label: label}
	life.attach(o)
	_ = ctx
	_ = mode
	_ = g
	return o, nil
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
// Non-fork RECVFROM: after the first datagram is delivered, further
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
func (u *unixRecvStream) SetWriteDeadline(t time.Time) error {
	return u.c.SetWriteDeadline(t)
}

// NetConn exposes the socket to xio's option lifecycle without making this
// pre-buffered stream a syscall.Conn. The relay must consume first before it
// polls the underlying socket, which is no longer readable after the opener's
// initial recvfrom.
func (u *unixRecvStream) NetConn() net.Conn { return u.c }

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
	// UNIX-RECVFROM,fork is one-shot: the
	// accepted datagram is already in first. Never read the shared parent
	// socket again — that would steal other peers' packets.
	return 0, io.EOF
}
func (u *unixPacketConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, fmt.Errorf("no peer")
	}
	u.deadlineMu.Lock()
	deadline := u.writeDeadline
	u.deadlineMu.Unlock()
	return writeSharedPacket(u.writeMu, deadline, u.c.SetWriteDeadline, func() (int, error) {
		return u.c.WriteToUnix(p, u.peer)
	})
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	var c *net.UnixConn
	if laddr != nil {
		c, err = listenUnixgramBound(s, laddr, false)
		if err != nil {
			return nil, err
		}
	} else {
		c, err = listenUnixgramUnbound(s)
		if err != nil {
			return nil, err
		}
	}
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: raddr, filterPeer: true, ctx: ctx}
	wrapped, err := xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
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
		// After-socket options (ApplySocketOptions / setsockopt-socket) are applied
		// after socket() in listen/dial Control or listenUnixgramUnbound.
		optionErr = xio.ApplyLateSocketOptions(int(fd), s)
		if optionErr == nil {
			optionErr = xio.ApplyGenericSetsockopt(int(fd), s, xio.SockoptPhaseConnected)
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	// FD then late options on the unixgram fd before wrapping.
	return xio.ApplyFDLifecycleToConn(c, s)
}

type unixgramConn struct {
	*net.UnixConn
	raddr      *net.UnixAddr
	filterPeer bool
	ctx        context.Context
}

func (u *unixgramConn) Read(p []byte) (int, error) {
	ctx := u.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		n, _, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UnixAddr, error) {
			nn, a, e := u.ReadFromUnix(p)
			return nn, nil, a, e
		})
		if err != nil {
			return n, err
		}
		if !u.filterPeer || unixgramAcceptSender(addr, u.raddr) {
			return n, nil
		}
	}
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

func unixgramAcceptSender(got, want *net.UnixAddr) bool {
	if want == nil {
		return true
	}
	if got == nil || unixgramUnnamed(got.Name) {
		return true
	}
	return unixAddr(got.Name) == unixAddr(want.Name)
}

func unixgramUnnamed(name string) bool {
	if name == "" {
		return true
	}
	if name[0] == 0 {
		return len(name) == 1
	}
	return name == "@"
}
