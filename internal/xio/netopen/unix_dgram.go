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

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio/sockopt"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func openUnixSendto(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixgramSend(ctx, s, mode, g, true)
}

func openUnixDatagram(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixgramSend(ctx, s, mode, g, false)
}

func openUnixgramSend(ctx context.Context, s addrconfig.Address, _ xio.Mode, _ *xio.Global, filterPeer bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("%s requires path", s.Type)
	}
	remote := unixAddr(s.Network.SocketPath)
	bindPath, err := resolveUnixBindConfig(s)
	if err != nil {
		return nil, err
	}
	bound := ""
	if bindPath != "" {
		bound = unixAddr(bindPath)
	}
	return finishUnixgramSend(ctx, s, &net.UnixAddr{Name: remote, Net: "unixgram"}, bound, filterPeer, s.Type+":"+remote)
}

// finishUnixgramSend binds an optional local name, applies socket options,
// and returns an unconnected unixgram stream aimed at remote.
func finishUnixgramSend(ctx context.Context, s addrconfig.Address, remote *net.UnixAddr, bindName string, filterPeer bool, label string) (*xio.Opened, error) {
	var c *net.UnixConn
	var err error
	if bindName != "" {
		if err = prepareUnixClientBind(bindName, s); err != nil {
			return nil, err
		}
		c, err = listenUnixgramBound(s, &net.UnixAddr{Name: bindName, Net: "unixgram"}, false)
	} else {
		c, err = listenUnixgramUnbound(s)
	}
	if err != nil {
		return nil, err
	}
	life := trackUnixBind(bindName, s)
	if err := applyUnixgramSocketOptions(c, s); err != nil {
		life.drop(c)
		return nil, err
	}
	if err := xio.ApplyConfiguredNamedAfterBind(bindName, s, nil); err != nil {
		life.drop(c)
		return nil, err
	}
	st := &unixgramConn{UnixConn: c, raddr: remote, filterPeer: filterPeer, ctx: ctx}
	wrapped, err := xio.WrapOpened(s, st)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	o, err := xio.NewReady(label, wrapped)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	life.attach(o)
	return o, nil
}

// listenUnixgramUnbound creates an unbound AF_UNIX SOCK_DGRAM socket and
// applies after-socket then before-bind options.
func listenUnixgramUnbound(s addrconfig.Address) (*net.UnixConn, error) {
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

func listenUnixgramBound(s addrconfig.Address, laddr *net.UnixAddr, applyUmask bool) (*net.UnixConn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyPastSocketThenPrebind(int(fd), s, "unixgram"); err != nil {
		logx.CloseErr(syscall.Close(fd))
		return nil, err
	}
	bind := func() error {
		return bindUnixPath(int(fd), laddr.Name, unixTightSocklen(s.Network.UnixTightSocklen))
	}
	if applyUmask {
		err = xio.WithConfiguredUmask(s.File, bind)
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
func openUnixRecvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, true)
}

// openUnixRecv: UNIX-RECV:path — bind, read-only (no reply).
func openUnixRecv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUnixRecvCommon(ctx, s, mode, g, false)
}

func openUnixRecvCommon(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global, from bool) (*xio.Opened, error) {
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("%s requires path", s.Type)
	}
	if !from && mode == xio.ModeWrite {
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	path := unixAddr(s.Network.SocketPath)
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
	if err := xio.ApplyConfiguredNamedAfterBind(path, s, nil); err != nil {
		life.drop(c)
		return nil, err
	}
	label := s.Type + ":" + path
	if xio.ForkRequested(s) && from {
		ln := &unixgramListener{c: c, path: path, config: s, g: g, ctx: ctx, nullEOF: s.Transfer.NullEOF.Value}
		d, terr := xio.RecvTimeout(s)
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
		o, err := xio.NewAcceptParent(label, xio.AcceptParent{
			ForkSocketpair: true,
			Listener:       ln,
			MaxChildren:    maxChildren,
			WrapDial:       xio.DefaultWrapOpened(s),
		})
		if err != nil {
			life.drop(ln)
			return nil, err
		}
		life.attach(o)
		return o, nil
	}

	if from {
		first, peer, err := waitUnixRecvfromPacket(ctx, c, g, s.Transfer.NullEOF.Value)
		if err != nil {
			life.drop(c)
			return nil, err
		}
		st := relay.Stream(&unixRecvStream{c: c, from: true, peer: peer, first: newFirstPacket(first)})
		wrapped, err := xio.WrapOpened(s, st)
		if err != nil {
			life.drop(c)
			return nil, err
		}
		o, err := xio.NewReady(label, wrapped)
		if err != nil {
			life.drop(c)
			return nil, err
		}
		life.attach(o)
		return o, nil
	}

	st := &unixRecvStream{c: c}
	wrapped, err := xio.WrapOpened(s, st)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	o, err := xio.NewReady(label, wrapped)
	if err != nil {
		life.drop(c)
		return nil, err
	}
	life.attach(o)
	return o, nil
}

func waitUnixRecvfromPacket(ctx context.Context, c *net.UnixConn, g *xio.Global, nullEOF bool) ([]byte, *net.UnixAddr, error) {
	buf := make([]byte, 65536)
	got := waitOneshotPacket(ctx, g, buf, func(buf []byte) (int, []byte, *net.UnixAddr, error) {
		n, addr, err := c.ReadFromUnix(buf)
		return n, nil, addr, err
	}, nil, nullEOF)
	if got.err != nil {
		return nil, nil, got.err
	}
	rememberUnixgramPeer(g, got.addr)
	return append([]byte(nil), buf[:got.n]...), got.addr, nil
}

func rememberUnixgramPeer(g *xio.Global, addr *net.UnixAddr) {
	if g == nil || addr == nil {
		return
	}
	if addr.Name != "" {
		g.Peer.PeerAddr = addr.Name
	} else {
		g.Peer.PeerAddr = addr.String()
	}
}

func cloneUnixAddr(a *net.UnixAddr) *net.UnixAddr {
	if a == nil {
		return nil
	}
	c := *a
	return &c
}

// unixRecvStream is UNIX-RECV (from=false: merge packets, read-only) or
// non-fork UNIX-RECVFROM (from=true: opener already received, then EOF;
// Write replies to that peer).
type unixRecvStream struct {
	c     *net.UnixConn
	from  bool
	peer  *net.UnixAddr
	first firstPacket
}

func (u *unixRecvStream) Read(p []byte) (int, error) {
	if first, ok := u.first.take(); ok {
		return copyOneshotFirst(p, first)
	}
	if u.from {
		return 0, io.EOF
	}
	n, _, err := u.c.ReadFromUnix(p)
	return n, err
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
	config     addrconfig.Address
	g          *xio.Global
	ctx        context.Context
	rcvTimeout time.Duration
	nullEOF    bool
	writeMu    sync.Mutex
}

func (l *unixgramListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65536)
	return recvfromForkAcceptor[*net.UnixAddr]{
		ctx:             l.ctx,
		rcvTimeout:      l.rcvTimeout,
		setReadDeadline: l.c.SetReadDeadline,
	}.acceptLoop(buf, func(buf []byte) (int, []byte, *net.UnixAddr, error) {
		n, addr, err := l.c.ReadFromUnix(buf)
		return n, nil, addr, err
	}, func(n int, _ []byte, buf []byte, addr *net.UnixAddr) acceptNext {
		if xio.IgnoreEmptyDatagram(n, nil, l.nullEOF) {
			return acceptAgain()
		}
		return acceptChild(l.newUnixOneshotChild(buf[:n], addr), nil)
	})
}

func (l *unixgramListener) newUnixOneshotChild(data []byte, peer *net.UnixAddr) *oneshotForkConn {
	peer = cloneUnixAddr(peer)
	session := l.g.ForkSession()
	rememberUnixgramPeer(session, peer)
	return newOneshotForkConn(
		append([]byte(nil), data...),
		l.c.LocalAddr(),
		peer,
		session,
		&l.writeMu,
		l.c.SetWriteDeadline,
		func(p []byte) (int, error) {
			if peer == nil {
				return 0, fmt.Errorf("no peer")
			}
			return l.c.WriteToUnix(p, peer)
		},
		nil,
	)
}
func (l *unixgramListener) Close() error {
	return l.c.Close()
}
func (l *unixgramListener) Addr() net.Addr {
	return &net.UnixAddr{Name: l.path, Net: "unixgram"}
}

// openAbstractRecvfrom: bind abstract datagram, one peer packet then reply (like UNIX-RECVFROM).
func openAbstractRecvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("ABSTRACT-RECVFROM requires name")
	}
	path := abstractName(s.Network.SocketPath)
	ps := s
	ps.Network.SocketPath = path
	// Force abstract path through openUnixRecvCommon without filesystem unlink.
	return openUnixRecvCommon(ctx, ps, mode, g, true)
}

// openAbstractRecv: bind abstract datagram, read-only merge of packets.
func openAbstractRecv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("ABSTRACT-RECV requires name")
	}
	path := abstractName(s.Network.SocketPath)
	ps := s
	ps.Network.SocketPath = path
	return openUnixRecvCommon(ctx, ps, mode, g, false)
}

// openAbstractSendto implements ABSTRACT-SENDTO[,bind=] datagram send.
func openAbstractSendto(ctx context.Context, s addrconfig.Address, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("ABSTRACT-SENDTO requires name")
	}
	target := abstractName(s.Network.SocketPath)
	bindOpt, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	bindName := ""
	if bindOpt != "" {
		bindName = abstractName(bindOpt)
	}
	return finishUnixgramSend(ctx, s, &net.UnixAddr{Name: target, Net: "unixgram"}, bindName, true, "ABSTRACT-SENDTO:"+s.Network.SocketPath)
}

func applyUnixgramSocketOptions(c *net.UnixConn, s addrconfig.Address) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		// After-socket options (ApplySocketOptions / setsockopt-socket) are applied
		// after socket() in listen/dial Control or listenUnixgramUnbound.
		optionErr = sockopt.ApplyLateSocketOptions(int(fd), s)
		if optionErr == nil {
			optionErr = sockopt.ApplyGenericSetsockopt(int(fd), s, sockopt.SockoptPhaseConnected)
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	// FD then late options on the unixgram fd before wrapping.
	return xio.ApplyFDLifecycleToConnSkip(c, s, xio.FDSkipNamedUnixSocket(s))
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
	// RecvOneCtx can return on cancel while ReadFromUnix is still blocked.
	// Receive into storage owned by that goroutine so an abandoned read
	// cannot write into a caller buffer the relay has already reused.
	return readScratchFiltered(ctx, p, func(buf []byte) (int, *net.UnixAddr, error) {
		return u.ReadFromUnix(buf)
	}, func(addr *net.UnixAddr) (bool, error) {
		if !u.filterPeer || unixgramAcceptSender(addr, u.raddr) {
			return true, nil
		}
		return false, nil
	})
}

func (u *unixgramConn) Write(p []byte) (int, error) {
	return u.WriteToUnix(p, u.raddr)
}
func (u *unixgramConn) ShutdownWrite() error { return nil }

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
