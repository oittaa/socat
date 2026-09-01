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

func applyUDPAcceptTimeout(pc *net.UDPConn, s parse.Spec) (bool, error) {
	timeout := xio.AcceptTimeout(s)
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
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	host, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	laddr, err := xio.ResolveUDPAddr(ctx, s, network, net.JoinHostPort(xio.StripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	pc, err := listenUDP(network, laddr, s)
	if err != nil {
		return nil, err
	}

	// fork: keep listening and spawn a session per first-packet "connection".
	if s.BoolOption("fork") {
		_, maxChildren, ferr := xio.ForkLimits(s)
		if ferr != nil {
			logx.CloseQuiet(pc)
			return nil, ferr
		}
		peerFilter := xio.NewPeerFilter(ctx, s, g)
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
				return xio.WrapCommonAfterConnected(s, udpConnectStream{NetStream: relay.NetStream{Conn: c}})
			},
		}, nil
	}
	timeoutSet, err := applyUDPAcceptTimeout(pc, s)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	xio.NoteListenBound(pc.LocalAddr())

	// Non-fork: one peer session. Keep the listen socket for further
	// packets from that peer and for replies.
	buf := make([]byte, max(g.BlockSize, 8192))
	wantCtrl := xio.NeedAncillary(s)
	var n int
	var raddr *net.UDPAddr
	peerFilter := xio.NewPeerFilter(ctx, s, g)
	var oobBuffer [xio.AncillaryBufferSize]byte
	for {
		rn, oob, a, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UDPAddr, error) {
			return xio.ReadUDPMsgWithBuffer(pc, buf, wantCtrl, oobBuffer[:])
		})
		if err != nil {
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
		first:    append([]byte(nil), buf[:n]...),
		wantCtrl: wantCtrl,
		g:        g,
	})
	st, err = xio.WrapCommonAfterConnected(s, st)
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

	mu            sync.Mutex
	handedOff     bool // reuseaddr=0: first session owns the listen socket
	listenClosed  bool
	exclusiveDone chan struct{}
}

func applyUDPForkTimeouts(ln *udpForkListener, s parse.Spec) error {
	d, err := xio.RecvTimeoutFromSpec(s)
	if err != nil {
		return err
	}
	ln.rcvTimeout = d
	if !ln.oneShot {
		ln.acceptTimeout = xio.AcceptTimeout(s)
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
	// the packet. A second exclusive bind would fail. The fd stays a ListenUDP
	// socket (Go will not treat a later connect(2) as connected), so replies
	// use WriteToUDP.
	_ = l.pc.SetReadDeadline(time.Time{})
	l.mu.Lock()
	if l.listenClosed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	child.pc = l.pc
	child.ownsListen = true
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

func (l *udpForkListener) Accept() (net.Conn, error) {
	if conn, err, done := l.waitIfHandedOff(); done {
		return conn, err
	}
	buf := make([]byte, 65535)
	wantCtrl := xio.NeedAncillary(l.spec)
	var oobBuffer [xio.AncillaryBufferSize]byte
	var acceptDeadline time.Time
	if l.acceptTimeout > 0 {
		acceptDeadline = time.Now().Add(l.acceptTimeout)
	}
	for {
		switch {
		case !acceptDeadline.IsZero():
			// Restart the listen accept-timeout after a refused peer.
			_ = l.pc.SetReadDeadline(acceptDeadline)
		case l.rcvTimeout > 0:
			_ = l.pc.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		rn, oob, a, err := xio.RecvOneCtx(l.ctx, func() (int, []byte, *net.UDPAddr, error) {
			return xio.ReadUDPMsgWithBuffer(l.pc, buf, wantCtrl, oobBuffer[:])
		})
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, err
			}
			// Keep the listener alive across its periodic receive deadline;
			// continue waiting while idle.
			if l.rcvTimeout > 0 && acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
				continue
			}
			if !acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, err
		}
		if err := l.peerAllowed(a); err != nil {
			if stop := logOrStopPeerFilter(l.ctx, l.g, err); stop != nil {
				return nil, stop
			}
			// Restart the listen accept-timeout after a refused peer.
			if l.acceptTimeout > 0 {
				acceptDeadline = time.Now().Add(l.acceptTimeout)
			}
			continue
		}
		session := &xio.Global{}
		if l.g != nil {
			session.Log = l.g.Log
			session.Progname = l.g.Progname
		}
		xio.ProcessAncillary(oob, session)
		child := &udpSessionConn{
			peer:     cloneUDPAddr(a),
			first:    append([]byte(nil), buf[:rn]...),
			env:      session.SessionVars,
			oneShot:  l.oneShot,
			writeMu:  &l.writeMu,
			wantCtrl: wantCtrl,
			g:        session,
		}
		if l.oneShot {
			// Share the parent socket (one-shot). A
			// connected child on the same port would steal later datagrams.
			child.pc = l.pc
			return child, nil
		}
		if !xio.UDPForkPortReuse(l.spec) {
			return l.handoffListenSocket(child)
		}
		local := l.laddr
		if la, ok := l.pc.LocalAddr().(*net.UDPAddr); ok {
			local = cloneUDPAddr(la)
		}
		conn, err := dialUDPSession(l.ctx, l.network, local, a, l.spec)
		if err != nil {
			if l.g != nil && l.g.Log != nil {
				l.g.Log.Noticef("UDP fork session dial: %s", err)
			}
			continue
		}
		child.conn = conn
		return child, nil
	}
}

func (l *udpForkListener) peerAllowed(addr *net.UDPAddr) error {
	if l.filter == nil {
		l.filter = xio.NewPeerFilter(l.ctx, l.spec, l.g)
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
	c, err := dialUDPForSpec(ctx, network, local, remote.String(), s, reuseControl, 0)
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
func (l *udpForkListener) oneShotMode() bool {
	return l.oneShot
}

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

// udpSessionConn is one UDP "connection" for fork children.
// Do NOT embed *net.UDPConn: poll would wait for POLLIN while the first
// datagram is only in first[] (already consumed from the listen socket).
// UDP-LISTEN,fork uses a connected child socket when the port can be shared.
// reuseaddr=0 hands off the listen socket (ownsListen): drain first, then
// ReadFromUDP / WriteToUDP. UDP-RECVFROM,fork shares the parent (oneShot):
// drain first, then EOF, and reply with WriteToUDP.
type udpSessionConn struct {
	conn       *net.UDPConn // connected child for UDP-LISTEN,fork with reuse
	pc         *net.UDPConn // RECVFROM share, or exclusive listen handoff
	ownsListen bool         // exclusive UDP-LISTEN,fork,reuseaddr=0
	peer       *net.UDPAddr
	first      []byte
	got        bool
	oneShot    bool
	closed     bool
	env        map[string]string

	writeMu       *sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	releaseListen func()
	wantCtrl      bool
	g             *xio.Global
	oob           []byte
}

func (u *udpSessionConn) SessionEnvironment() map[string]string { return u.env }

func (u *udpSessionConn) Read(p []byte) (int, error) {
	if !u.got && len(u.first) > 0 {
		u.got = true
		n := copy(p, u.first)
		u.first = nil
		return n, nil
	}
	if u.oneShot {
		// UDP-RECVFROM,fork is one-shot: drain first, then EOF.
		return 0, io.EOF
	}
	if u.ownsListen {
		return u.readHandedOff(p)
	}
	if u.conn == nil {
		return 0, net.ErrClosed
	}
	if u.wantCtrl {
		n, oob, _, err := xio.ReadUDPMsgWithBuffer(u.conn, p, true, ancillaryBuffer(&u.oob, true))
		if err != nil {
			return n, err
		}
		xio.ProcessAncillary(oob, u.g)
		return n, nil
	}
	return u.conn.Read(p)
}

func (u *udpSessionConn) readHandedOff(p []byte) (int, error) {
	if u.pc == nil {
		return 0, net.ErrClosed
	}
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.pc, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			return n, err
		}
		if udpAddrIsPeer(addr, u.peer) {
			if u.wantCtrl {
				xio.ProcessAncillary(oob, u.g)
			}
			return n, nil
		}
	}
}

func (u *udpSessionConn) Write(p []byte) (int, error) {
	if u.conn != nil {
		return u.conn.Write(p)
	}
	if u.pc == nil || u.peer == nil {
		return 0, net.ErrClosed
	}
	u.deadlineMu.Lock()
	deadline := u.writeDeadline
	u.deadlineMu.Unlock()
	return writeSharedPacket(u.writeMu, deadline, u.pc.SetWriteDeadline, func() (int, error) {
		return u.pc.WriteToUDP(p, u.peer)
	})
}

func (u *udpSessionConn) Close() error {
	if u.closed {
		return nil
	}
	u.closed = true
	if u.oneShot {
		return nil // parent owns the listen socket
	}
	var err error
	if u.conn != nil {
		err = u.conn.Close()
	}
	if u.ownsListen && u.pc != nil {
		// Keep pc set: Transfer pokes SetReadDeadline from another
		// goroutine after Close (UDP has no EOF).
		err = errors.Join(err, u.pc.Close())
	}
	if u.releaseListen != nil {
		u.releaseListen()
	}
	return err
}

func (u *udpSessionConn) LocalAddr() net.Addr {
	if u.conn != nil {
		return u.conn.LocalAddr()
	}
	if u.pc != nil {
		return u.pc.LocalAddr()
	}
	return nil
}
func (u *udpSessionConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpSessionConn) SetDeadline(t time.Time) error {
	if u.oneShot {
		return u.SetWriteDeadline(t)
	}
	if err := u.SetReadDeadline(t); err != nil {
		return err
	}
	return u.SetWriteDeadline(t)
}
func (u *udpSessionConn) SetReadDeadline(t time.Time) error {
	if u.oneShot {
		// Read never touches the shared listener; do not install a deadline on it.
		return nil
	}
	if u.ownsListen {
		if u.pc == nil {
			return net.ErrClosed
		}
		return u.pc.SetReadDeadline(t)
	}
	if u.conn == nil {
		return net.ErrClosed
	}
	return u.conn.SetReadDeadline(t)
}
func (u *udpSessionConn) SetWriteDeadline(t time.Time) error {
	if u.conn != nil {
		return u.conn.SetWriteDeadline(t)
	}
	u.deadlineMu.Lock()
	u.writeDeadline = t
	u.deadlineMu.Unlock()
	return nil
}

// udpRecvFromConn: first datagram already received; further Read/Write use the
// listening socket with WriteTo to the peer (no rebinding).
// Named field (not embed) so poll does not wait for POLLIN while first is buffered.
type udpRecvFromConn struct {
	uc       *net.UDPConn
	peer     *net.UDPAddr
	first    []byte
	closeEOF bool // after first payload: further Read → EOF (UDP-RECVFROM one-shot)
	wantCtrl bool
	g        *xio.Global
	oob      []byte
}

func (u *udpRecvFromConn) Read(p []byte) (int, error) {
	if len(u.first) > 0 {
		n := copy(p, u.first)
		u.first = nil
		return n, nil
	}
	if u.closeEOF {
		// UDP-RECVFROM is one-shot: drain first, then EOF.
		return 0, io.EOF
	}
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.uc, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			return n, err
		}
		if udpAddrIsPeer(addr, u.peer) {
			if u.wantCtrl {
				xio.ProcessAncillary(oob, u.g)
			}
			return n, nil
		}
	}
}

func (u *udpRecvFromConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, net.ErrClosed
	}
	return u.uc.WriteToUDP(p, u.peer)
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
