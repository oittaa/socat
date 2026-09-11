package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s))
}
func openUDP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp6")
}

func applyUDPAcceptTimeout(ctx context.Context, pc *net.UDPConn, s parse.Spec) (bool, error) {
	timeout := xio.AcceptTimeout(ctx, s)
	if timeout <= 0 {
		return false, nil
	}
	if err := pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("accept-timeout: %w", err)
	}
	return true, nil
}

func clearUDPAcceptTimeout(pc *net.UDPConn, set bool) error {
	if !set {
		return nil
	}
	return pc.SetReadDeadline(time.Time{})
}

func udpAcceptError(err error, timeoutSet bool) error {
	if timeoutSet && xio.IsTimeoutErr(err) {
		return xio.ErrAcceptTimeout
	}
	return err
}

func openUDPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	pc, laddr, err := bindUDPPort(ctx, s, network)
	if err != nil {
		return nil, err
	}
	if s.BoolOption("fork") {
		return openUDPListenFork(ctx, s, g, pc, laddr, network)
	}
	return openUDPListenOnePeer(ctx, s, g, pc, network)
}

func bindUDPPort(ctx context.Context, s parse.Spec, network string) (*net.UDPConn, *net.UDPAddr, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, nil, fmt.Errorf("%s requires port", s.Type)
	}
	host, err := xio.ListenBindHost(s, network, "")
	if err != nil {
		return nil, nil, err
	}
	laddr, err := xio.ResolveUDPAddr(ctx, s, network, net.JoinHostPort(xio.StripBrackets(host), s.Params[0]))
	if err != nil {
		return nil, nil, err
	}
	pc, err := listenUDP(network, laddr, s)
	if err != nil {
		return nil, nil, err
	}
	return pc, laddr, nil
}

func openUDPListenFork(ctx context.Context, s parse.Spec, g *xio.Global, pc *net.UDPConn, laddr *net.UDPAddr, network string) (*xio.Opened, error) {
	if udpForkSharesListenSocket() && xio.ShutDownSelected(s) {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP-LISTEN,fork,shut-down: not supported")
	}
	_, maxChildren, ferr := xio.ForkLimits(ctx, s)
	if ferr != nil {
		logx.CloseQuiet(pc)
		return nil, ferr
	}
	peerFilter, err := xio.PreparedPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	base := &udpForkListener{
		pc:      pc,
		network: network,
		laddr:   laddr,
		spec:    s,
		g:       g,
		ctx:     ctx,
		filter:  peerFilter,
	}
	if err := applyUDPForkTimeouts(base, s); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	ln := newUDPListenForkListener(base)
	xio.NoteListenBound(pc.LocalAddr())
	return &xio.Opened{
		Kind:        xio.KindListen,
		Listener:    ln,
		Label:       "UDP-LISTEN",
		MaxChildren: maxChildren,
		PeerFilter:  peerFilter.AllowConn,
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapOpened(s, udpConnectStream{NetStream: relay.NetStream{Conn: c}})
		},
	}, nil
}

func openUDPListenOnePeer(ctx context.Context, s parse.Spec, g *xio.Global, pc *net.UDPConn, network string) (*xio.Opened, error) {
	xio.NoteListenBound(pc.LocalAddr())

	// Resolve range= before the accept deadline. Slow DNS must not consume
	// accept-timeout; a datagram can already be queued while lookup runs.
	peerFilter, err := xio.PreparedPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	timeoutSet, err := applyUDPAcceptTimeout(ctx, pc, s)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}

	// Non-fork: one peer session. Keep the listen socket for further
	// packets from that peer and for replies.
	buf := make([]byte, max(g.BlockSize, 8192))
	wantCtrl := xio.NeedAncillary(s)
	recvErr := xio.NeedRecvErr(s)
	var n int
	var raddr *net.UDPAddr
	var oobBuffer [xio.AncillaryBufferSize]byte
	for {
		rn, oob, a, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UDPAddr, error) {
			return xio.ReadUDPMsgWithBuffer(pc, buf, wantCtrl, oobBuffer[:])
		})
		if err != nil {
			xio.DrainRecvErrOnError(err, recvErr, pc, g)
			logx.CloseQuiet(pc)
			return nil, udpAcceptError(err, timeoutSet)
		}
		if ferr := peerFilter.AllowAddr(a, pc.LocalAddr()); ferr != nil {
			if stop := logOrStopPeerFilter(ctx, g, ferr); stop != nil {
				logx.CloseQuiet(pc)
				return nil, udpAcceptError(stop, timeoutSet)
			}
			continue
		}
		n, raddr = rn, a
		xio.ProcessAncillary(oob, g)
		break
	}
	if err := clearUDPAcceptTimeout(pc, timeoutSet); err != nil {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("accept-timeout: clear deadline: %w", err)
	}
	if err := connectUDPPeer(pc, raddr); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	// SOCAT_* env for EXEC/SYSTEM children (UDP6LISTENENV etc.).
	// When bound to unspecified (:: / 0.0.0.0), still report the
	// local address used for this peer (loopback peer → loopback sock).
	if g != nil {
		if raddr != nil {
			g.PeerAddr = xio.FormatSocatAddr(raddr.IP.String())
			g.PeerPort = strconv.Itoa(raddr.Port)
		}
		if la := pc.LocalAddr(); la != nil {
			if host, p, e := net.SplitHostPort(la.String()); e == nil {
				g.SockPort = p
				lip := net.ParseIP(xio.StripBrackets(host))
				if lip != nil && lip.IsUnspecified() && raddr != nil {
					localIP := udpRouteLocalIP(network, raddr)
					if localIP == nil {
						localIP = lip
					}
					g.SockAddr = xio.FormatSocatAddr(localIP.String())
				} else {
					g.SockAddr = xio.FormatSocatAddr(host)
				}
			}
		}
	}
	st := relay.Stream(&udpRecvFromConn{
		uc:       pc,
		peer:     raddr,
		first:    newFirstPacket(append([]byte(nil), buf[:n]...)),
		wantCtrl: wantCtrl,
		recvErr:  recvErr,
		g:        g,
	})
	st, err = xio.WrapOpened(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "UDP-LISTEN"}, nil
}

// udpRouteLocalIP is the local address a wildcard listener would use for this
// peer. A route-only UDP dial does not send a packet, but selects the same
// local interface address. Falling back to the bound address is preferable
// to misreporting the peer as local.
func udpRouteLocalIP(network string, peer *net.UDPAddr) net.IP {
	if peer == nil {
		return nil
	}
	c, err := net.DialUDP(network, nil, peer)
	if err != nil {
		return nil
	}
	defer logx.CloseQuiet(c)
	if local, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return local.IP
	}
	return nil
}

// udpForkListener implements net.Listener for UDP-LISTEN/RECVFROM,fork:
// each Accept waits for a datagram and returns a session Conn for that peer.
// UDP-LISTEN,fork children use udpSessionConn: connected (reuse child socket)
// or exclusive handoff (reuseaddr=0). UDP-RECVFROM,fork uses oneshotForkConn
// so the parent keeps the listen fd. Darwin/Windows may wrap this in
// udpDispatchListener instead of connecting a child socket.
type udpForkPacket struct {
	data []byte
	oob  []byte
	peer *net.UDPAddr
}

type udpForkListener struct {
	pc            *net.UDPConn
	network       string
	laddr         *net.UDPAddr
	spec          parse.Spec
	g             *xio.Global
	ctx           context.Context
	rcvTimeout    time.Duration
	acceptTimeout time.Duration
	oneShot       bool // UDP-RECVFROM,fork: one datagram then EOF
	filter        *xio.PeerFilter
	writeMu       sync.Mutex
	pending       []udpForkPacket

	mu            sync.Mutex
	handedOff     bool // reuseaddr=0: first session owns Close of pc
	listenClosed  bool
	exclusiveDone chan struct{}
}

const (
	// A transient resource failure must not lose UDP-LISTEN's opener. Retry it
	// once, then discard that datagram so a persistent failure cannot spin.
	udpForkDialMaxAttempts = 2

	// Match the bounded Darwin/Windows dispatcher queues. The drain budget also
	// keeps one Accept from copying an endless stream out of SO_RCVBUF.
	udpForkSessionQueueSize = 64
	udpForkPendingQueueSize = 256
	udpForkDrainPacketLimit = 256
)

func (l *udpForkListener) appendPending(packet udpForkPacket) bool {
	if len(l.pending) >= udpForkPendingQueueSize {
		return false
	}
	l.pending = append(l.pending, packet)
	return true
}

func (l *udpForkListener) prependPending(packet udpForkPacket) {
	l.pending = append([]udpForkPacket{packet}, l.pending...)
	if len(l.pending) > udpForkPendingQueueSize {
		l.pending = l.pending[:udpForkPendingQueueSize]
	}
}

func appendUDPForkSessionPacket(child *udpSessionConn, packet udpForkPacket) bool {
	if len(child.queued) >= udpForkSessionQueueSize {
		return false
	}
	child.queued = append(child.queued, packet)
	return true
}

func applyUDPForkTimeouts(ln *udpForkListener, s parse.Spec) error {
	d, err := xio.RecvTimeoutFromSpec(ln.ctx, s)
	if err != nil {
		return err
	}
	ln.rcvTimeout = d
	if !ln.oneShot {
		ln.acceptTimeout = xio.AcceptTimeout(ln.ctx, s)
	}
	return nil
}

func (l *udpForkListener) waitIfHandedOff() (net.Conn, error, bool) {
	l.mu.Lock()
	if !l.handedOff {
		l.mu.Unlock()
		return nil, nil, false
	}
	done := l.exclusiveDone
	l.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-l.ctx.Done():
			return nil, l.ctx.Err(), true
		}
	}
	return nil, net.ErrClosed, true
}

func (l *udpForkListener) signalExclusiveDone() {
	if l.exclusiveDone != nil {
		close(l.exclusiveDone)
		l.exclusiveDone = nil
	}
}

func (l *udpForkListener) handoffListenSocket(child *udpSessionConn) (net.Conn, error) {
	// reuseaddr=0: the first session takes this listen fd instead of dropping
	// the packet. A second exclusive bind would fail. Connect the fd to the
	// peer so shut-down can call shutdown(SHUT_WR).
	_ = l.pc.SetReadDeadline(time.Time{})
	if err := connectUDPPeer(l.pc, child.peer); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.listenClosed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	child.setHandoff(l.pc)
	l.handedOff = true
	l.exclusiveDone = make(chan struct{})
	done := l.exclusiveDone
	l.mu.Unlock()
	child.releaseListen = func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.exclusiveDone == done {
			l.signalExclusiveDone()
		}
	}
	return child, nil
}

func (l *udpForkListener) newUDPOneshotChild(pc *net.UDPConn, packet udpForkPacket, session *xio.Global) *oneshotForkConn {
	peer := cloneUDPAddr(packet.peer)
	local := pc.LocalAddr()
	if local == nil && l.laddr != nil {
		local = l.laddr
	}
	recvErr := xio.NeedRecvErr(l.spec)
	return newOneshotForkConn(
		append([]byte(nil), packet.data...),
		local,
		peer,
		session,
		&l.writeMu,
		pc.SetWriteDeadline,
		func(p []byte) (int, error) { return writeToUDPWithFallback(pc, p, peer) },
		func(err error) { xio.DrainRecvErrOnError(err, recvErr, pc, session) },
	)
}

func (l *udpForkListener) newUDPForkChild(packet udpForkPacket, session *xio.Global, wantCtrl, recvErr bool) *udpSessionConn {
	return &udpSessionConn{
		role:     udpRoleConnected,
		peer:     cloneUDPAddr(packet.peer),
		first:    newFirstPacket(append([]byte(nil), packet.data...)),
		env:      session.SessionVarsSnapshot(),
		writeMu:  &l.writeMu,
		wantCtrl: wantCtrl,
		recvErr:  recvErr,
		g:        session,
	}
}

func (l *udpForkListener) peerAllowed(addr *net.UDPAddr) error {
	if l.filter == nil {
		f, err := xio.PreparedPeerFilter(l.ctx, l.spec, l.g)
		if err != nil {
			return err
		}
		l.filter = f
	}
	return l.filter.AllowAddr(addr, l.pc.LocalAddr())
}

func dialUDPSession(ctx context.Context, network string, local, remote *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
	// SO_REUSEADDR so we can bind the same local port as the parent listener.
	// Skip when reuseaddr=0: the explicit zero stays exclusive and does not
	// enable SO_REUSEPORT for parent/child sharing.
	reuseControl := func(_ string, _ string, c syscall.RawConn) error {
		var optionErr error
		controlErr := c.Control(func(fd uintptr) {
			if !xio.UDPForkPortReuse(s) {
				return
			}
			optionErr = xio.SetSockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if optionErr == nil {
				optionErr = enableUDPForkPortReuse(int(fd))
			}
		})
		return errors.Join(controlErr, optionErr)
	}
	// The child is a new socket, not the parent listener fd. Apply every
	// after-socket option again on this fd before bind/connect, then the
	// fork-specific reuse flags.
	c, err := dialUDPForSpec(dialRequest{
		ctx:     ctx,
		network: network,
		spec:    s,
		control: reuseControl,
	}, local, remote.String())
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(c)
		return nil, fmt.Errorf("UDP session: unexpected conn type")
	}
	if err := xio.ApplyUDPConnOpts(uc, s, network); err != nil {
		logx.CloseQuiet(uc)
		return nil, err
	}
	return uc, nil
}

func (l *udpForkListener) Close() error {
	l.mu.Lock()
	l.signalExclusiveDone()
	if l.handedOff {
		l.mu.Unlock()
		// First exclusive session owns the listen socket.
		return nil
	}
	if l.listenClosed {
		l.mu.Unlock()
		return nil
	}
	l.listenClosed = true
	pc := l.pc
	l.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.Close()
}
func (l *udpForkListener) Addr() net.Addr { return l.pc.LocalAddr() }

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	c := *a
	if a.IP != nil {
		c.IP = append(net.IP(nil), a.IP...)
	}
	return &c
}

// udpSessionRole is how a fork child uses a UDP socket.
type udpSessionRole int

const (
	// udpRoleConnected: dedicated connected child (UDP-LISTEN,fork with reuse).
	udpRoleConnected udpSessionRole = iota
	// udpRoleHandoff: exclusive listen fd; child Closes it (reuseaddr=0).
	udpRoleHandoff
)

// udpSessionConn is one UDP "connection" for fork children.
// Do NOT embed *net.UDPConn: sessions can have datagrams buffered outside the
// socket while UDP-LISTEN routes packets received during child setup.
type udpSessionConn struct {
	role      udpSessionRole
	sock      *net.UDPConn
	peer      *net.UDPAddr
	first     firstPacket
	closeOnce sync.Once
	closeErr  error
	env       map[string]string

	writeMu       *sync.Mutex
	writeDL       sharedWriteDeadline
	releaseListen func()
	wantCtrl      bool
	recvErr       bool
	queued        []udpForkPacket
	g             *xio.Global
	oob           []byte
}

func (u *udpSessionConn) setConnected(c *net.UDPConn) {
	u.role = udpRoleConnected
	u.sock = c
}

func (u *udpSessionConn) setHandoff(c *net.UDPConn) {
	u.role = udpRoleHandoff
	u.sock = c
}

func (u *udpSessionConn) SessionEnvironment() map[string]string {
	if u.g != nil {
		return u.g.SessionVarsSnapshot()
	}
	return u.env
}

func (u *udpSessionConn) drainRecvErr(err error) {
	xio.DrainRecvErrOnError(err, u.recvErr, u.recvErrConn(), u.g)
}

func (u *udpSessionConn) recvErrConn() syscall.Conn {
	return u.sock
}

func (u *udpSessionConn) Read(p []byte) (int, error) {
	if first, ok := u.first.take(); ok {
		n := copy(p, first)
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	if len(u.queued) > 0 {
		packet := u.queued[0]
		u.queued = u.queued[1:]
		if u.wantCtrl {
			xio.ProcessAncillary(packet.oob, u.g)
		}
		n := copy(p, packet.data)
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	if u.role == udpRoleHandoff {
		return u.readHandedOff(p)
	}
	if u.sock == nil {
		return 0, net.ErrClosed
	}
	if u.wantCtrl {
		n, oob, _, err := xio.ReadUDPMsgWithBuffer(u.sock, p, true, ancillaryBuffer(&u.oob, true))
		if err != nil {
			u.drainRecvErr(err)
			return n, err
		}
		xio.ProcessAncillary(oob, u.g)
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	n, err := u.sock.Read(p)
	if err != nil {
		u.drainRecvErr(err)
	}
	return xio.ZeroLengthMessageEOF(n, err, len(p))
}

func (u *udpSessionConn) readHandedOff(p []byte) (int, error) {
	if u.sock == nil {
		return 0, net.ErrClosed
	}
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.sock, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			u.drainRecvErr(err)
			return n, err
		}
		if udpAddrIsPeer(addr, u.peer) {
			if u.wantCtrl {
				xio.ProcessAncillary(oob, u.g)
			}
			return xio.ZeroLengthMessageEOF(n, nil, len(p))
		}
	}
}

func (u *udpSessionConn) Write(p []byte) (int, error) {
	if u.role == udpRoleConnected {
		if u.sock == nil {
			return 0, net.ErrClosed
		}
		n, err := u.sock.Write(p)
		u.drainRecvErr(err)
		return n, err
	}
	if u.sock == nil || u.peer == nil {
		return 0, net.ErrClosed
	}
	n, err := writeSharedPacket(u.writeMu, u.writeDL.get(), u.sock.SetWriteDeadline, func() (int, error) {
		return writeToUDPWithFallback(u.sock, p, u.peer)
	})
	u.drainRecvErr(err)
	return n, err
}

func (u *udpSessionConn) Close() error {
	u.closeOnce.Do(func() {
		var err error
		if u.sock != nil {
			// Keep sock set: Transfer pokes SetReadDeadline from another
			// goroutine after Close (UDP has no EOF).
			err = u.sock.Close()
		}
		if u.releaseListen != nil {
			u.releaseListen()
		}
		u.closeErr = err
	})
	return u.closeErr
}

func (u *udpSessionConn) LocalAddr() net.Addr {
	if u.sock != nil {
		return u.sock.LocalAddr()
	}
	return nil
}
func (u *udpSessionConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpSessionConn) SetDeadline(t time.Time) error {
	if err := u.SetReadDeadline(t); err != nil {
		return err
	}
	return u.SetWriteDeadline(t)
}
func (u *udpSessionConn) SetReadDeadline(t time.Time) error {
	if u.sock == nil {
		return net.ErrClosed
	}
	return u.sock.SetReadDeadline(t)
}
func (u *udpSessionConn) SetWriteDeadline(t time.Time) error {
	if u.role == udpRoleConnected && u.sock != nil {
		return u.sock.SetWriteDeadline(t)
	}
	u.writeDL.set(t)
	return nil
}

func (u *udpSessionConn) NetConn() net.Conn {
	return u.sock
}

// udpRecvFromConn: first datagram already received; further Read/Write use the
// listening socket with WriteTo to the peer (no rebinding).
// Named field (not embed) so poll does not wait for POLLIN while first is buffered.
type udpRecvFromConn struct {
	uc       *net.UDPConn
	peer     *net.UDPAddr
	first    firstPacket
	closeEOF bool // after first payload: further Read → EOF (UDP-RECVFROM one-shot)
	wantCtrl bool
	recvErr  bool
	g        *xio.Global
	oob      []byte
}

func (u *udpRecvFromConn) Read(p []byte) (int, error) {
	if first, ok := u.first.take(); ok {
		if u.closeEOF {
			return copyOneshotFirst(p, first)
		}
		n := copy(p, first)
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	if u.closeEOF {
		// UDP-RECVFROM is one-shot: drain first, then EOF.
		return 0, io.EOF
	}
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.uc, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			xio.DrainRecvErrOnError(err, u.recvErr, u.uc, u.g)
			return n, err
		}
		if udpAddrIsPeer(addr, u.peer) {
			if u.wantCtrl {
				xio.ProcessAncillary(oob, u.g)
			}
			return xio.ZeroLengthMessageEOF(n, nil, len(p))
		}
	}
}

func (u *udpRecvFromConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, net.ErrClosed
	}
	n, err := writeToUDPWithFallback(u.uc, p, u.peer)
	if err != nil {
		xio.DrainRecvErrOnError(err, u.recvErr, u.uc, u.g)
	}
	return n, err
}

func (u *udpRecvFromConn) Close() error { return u.uc.Close() }

func (u *udpRecvFromConn) ShutdownWrite() error {
	if u.closeEOF {
		return nil
	}
	_, _ = u.Write(nil)
	return nil
}
func (u *udpRecvFromConn) LocalAddr() net.Addr  { return u.uc.LocalAddr() }
func (u *udpRecvFromConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpRecvFromConn) SetDeadline(t time.Time) error {
	return u.uc.SetDeadline(t)
}
func (u *udpRecvFromConn) SetReadDeadline(t time.Time) error {
	return u.uc.SetReadDeadline(t)
}
func (u *udpRecvFromConn) SetWriteDeadline(t time.Time) error {
	return u.uc.SetWriteDeadline(t)
}

// NetConn exposes the socket to xio's option lifecycle without making this
// pre-buffered stream a syscall.Conn. The relay must consume first before it
// polls the underlying socket, which is no longer readable after the opener's
// initial recvfrom.
func (u *udpRecvFromConn) NetConn() net.Conn { return u.uc }
