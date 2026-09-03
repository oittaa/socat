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
		if udpForkSharesListenSocket() && xio.ShutDownSelected(s) {
			logx.CloseQuiet(pc)
			return nil, fmt.Errorf("UDP-LISTEN,fork,shut-down: not supported")
		}
		_, maxChildren, ferr := xio.ForkLimits(s)
		if ferr != nil {
			logx.CloseQuiet(pc)
			return nil, ferr
		}
		peerFilter, err := xio.NewCompiledPeerFilter(ctx, s, g)
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
	peerFilter, err := xio.NewCompiledPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
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
		uc:           pc,
		peer:         raddr,
		first:        append([]byte(nil), buf[:n]...),
		firstPending: true,
		wantCtrl:     wantCtrl,
		g:            g,
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
	dialSession   func(context.Context, string, *net.UDPAddr, *net.UDPAddr, parse.Spec) (*net.UDPConn, error)

	mu            sync.Mutex
	handedOff     bool // reuseaddr=0: first session owns the listen socket
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
	pc := l.pc
	if pc == nil {
		return nil, net.ErrClosed
	}
	buf := make([]byte, 65535)
	wantCtrl := xio.NeedAncillary(l.spec)
	peekDial := !l.oneShot && xio.UDPForkPortReuse(l.spec) && udpForkUsesPeekDial()
	var oobBuffer [xio.AncillaryBufferSize]byte
	var acceptDeadline time.Time
	if l.acceptTimeout > 0 {
		acceptDeadline = time.Now().Add(l.acceptTimeout)
	}
	var failedDialPeer *net.UDPAddr
	failedDialAttempts := 0
	for {
		switch {
		case !acceptDeadline.IsZero():
			// Restart the listen accept-timeout after a refused peer.
			_ = pc.SetReadDeadline(acceptDeadline)
		case l.rcvTimeout > 0:
			_ = pc.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}

		var packet udpForkPacket
		consumed := false
		var rn int
		var a *net.UDPAddr
		if peekDial && len(l.pending) > 0 {
			packet = l.pending[0]
			l.pending = l.pending[1:]
			consumed = true
			rn, a = len(packet.data), packet.peer
		} else {
			var readOOB []byte
			var err error
			rn, readOOB, a, err = xio.RecvOneCtx(l.ctx, func() (int, []byte, *net.UDPAddr, error) {
				return readUDPForkOpener(pc, buf, wantCtrl, oobBuffer[:], peekDial)
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
			if !peekDial {
				packet = udpForkPacket{
					data: append([]byte(nil), buf[:rn]...),
					oob:  append([]byte(nil), readOOB...),
					peer: cloneUDPAddr(a),
				}
				consumed = true
			}
		}

		if err := l.peerAllowed(a); err != nil {
			if peekDial && !consumed {
				// The opener was only peeked. Consume the refused datagram or the
				// next loop would inspect the same peer forever.
				if _, _, _, dropErr := xio.ReadUDPMsgWithBuffer(pc, buf, false, nil); dropErr != nil {
					return nil, dropErr
				}
			}
			if stop := logOrStopPeerFilter(l.ctx, l.g, err); stop != nil {
				return nil, stop
			}
			// Restart the listen accept-timeout after a refused peer.
			if l.acceptTimeout > 0 {
				acceptDeadline = time.Now().Add(l.acceptTimeout)
			}
			continue
		}
		if l.oneShot && xio.IgnoreEmptyDatagram(rn, nil, l.spec.BoolOption("null-eof")) {
			continue
		}

		session := &xio.Global{}
		if l.g != nil {
			session.Log = l.g.Log
			session.Progname = l.g.Progname
		}

		if l.oneShot {
			xio.ProcessAncillary(packet.oob, session)
			child := l.newUDPForkChild(packet, session, wantCtrl)
			// Share the parent socket (one-shot). A
			// connected child on the same port would steal later datagrams.
			child.pc = pc
			return child, nil
		}
		if !xio.UDPForkPortReuse(l.spec) {
			xio.ProcessAncillary(packet.oob, session)
			child := l.newUDPForkChild(packet, session, wantCtrl)
			return l.handoffListenSocket(child)
		}
		if !peekDial {
			return nil, fmt.Errorf("UDP fork listener: peek-before-dial unavailable")
		}

		local := l.laddr
		if la, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			local = cloneUDPAddr(la)
		}
		dialSession := l.dialSession
		if dialSession == nil {
			dialSession = dialUDPSession
		}
		conn, err := dialSession(l.ctx, l.network, local, a, l.spec)
		if err != nil {
			if udpAddrIsPeer(a, failedDialPeer) {
				failedDialAttempts++
			} else {
				failedDialPeer = cloneUDPAddr(a)
				failedDialAttempts = 1
			}
			if failedDialAttempts < udpForkDialMaxAttempts {
				if consumed {
					l.prependPending(packet)
				}
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("UDP fork session dial: %s; retrying opener", err)
				}
				continue
			}
			if !consumed {
				// Remove the opener that MSG_PEEK left on the socket. Preserve an
				// unexpected packet rather than dropping a different peer.
				n, dropOOB, peer, ok, dropErr := readQueuedUDPForkPacket(pc, buf, wantCtrl, oobBuffer[:])
				if dropErr != nil {
					return nil, dropErr
				}
				if ok && !udpAddrIsPeer(peer, a) {
					l.appendPending(udpForkPacket{
						data: append([]byte(nil), buf[:n]...),
						oob:  append([]byte(nil), dropOOB...),
						peer: cloneUDPAddr(peer),
					})
				}
			}
			if l.g != nil && l.g.Log != nil {
				l.g.Log.Noticef("UDP fork session dial: %s; dropping opener after %d attempts", err, failedDialAttempts)
			}
			failedDialPeer = nil
			failedDialAttempts = 0
			continue
		}
		failedDialPeer = nil
		failedDialAttempts = 0

		if !consumed {
			rn, oob, peer, ok, err := readQueuedUDPForkPacket(pc, buf, wantCtrl, oobBuffer[:])
			if err != nil {
				logx.CloseQuiet(conn)
				return nil, err
			}
			if !ok {
				logx.CloseQuiet(conn)
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("UDP fork opener disappeared before session handoff")
				}
				continue
			}
			packet = udpForkPacket{
				data: append([]byte(nil), buf[:rn]...),
				oob:  append([]byte(nil), oob...),
				peer: cloneUDPAddr(peer),
			}
			if !udpAddrIsPeer(packet.peer, a) {
				logx.CloseQuiet(conn)
				l.appendPending(packet)
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("UDP fork opener changed from %s to %s; preserving received packet", a, packet.peer)
				}
				continue
			}
		}

		xio.ProcessAncillary(packet.oob, session)
		child := l.newUDPForkChild(packet, session, wantCtrl)
		child.conn = conn
		if len(l.pending) > 0 {
			remaining := make([]udpForkPacket, 0, len(l.pending))
			for _, queued := range l.pending {
				if udpAddrIsPeer(queued.peer, child.peer) {
					appendUDPForkSessionPacket(child, queued)
				} else {
					remaining = append(remaining, queued)
				}
			}
			l.pending = remaining
		}
		for range udpForkDrainPacketLimit {
			n, queuedOOB, peer, ok, drainErr := readQueuedUDPForkPacket(pc, buf, wantCtrl, oobBuffer[:])
			if drainErr != nil {
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("UDP fork listener queue drain: %s", drainErr)
				}
				break
			}
			if !ok {
				break
			}
			queued := udpForkPacket{
				data: append([]byte(nil), buf[:n]...),
				oob:  append([]byte(nil), queuedOOB...),
				peer: cloneUDPAddr(peer),
			}
			if udpAddrIsPeer(peer, child.peer) {
				appendUDPForkSessionPacket(child, queued)
			} else {
				l.appendPending(queued)
			}
		}
		return child, nil
	}
}

func (l *udpForkListener) newUDPForkChild(packet udpForkPacket, session *xio.Global, wantCtrl bool) *udpSessionConn {
	return &udpSessionConn{
		peer:         cloneUDPAddr(packet.peer),
		first:        append([]byte(nil), packet.data...),
		firstPending: true,
		env:          session.SessionVars,
		oneShot:      l.oneShot,
		writeMu:      &l.writeMu,
		wantCtrl:     wantCtrl,
		g:            session,
	}
}

func (l *udpForkListener) peerAllowed(addr *net.UDPAddr) error {
	if l.filter == nil {
		f, err := xio.NewCompiledPeerFilter(l.ctx, l.spec, l.g)
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
// Do NOT embed *net.UDPConn: sessions can have datagrams buffered outside the
// socket while UDP-LISTEN routes packets received during child setup.
// reuseaddr=0 hands off the listen socket (ownsListen): drain first, then
// ReadFromUDP / WriteToUDP. UDP-RECVFROM,fork shares the parent (oneShot):
// drain first, then EOF, and reply with WriteToUDP.
type udpSessionConn struct {
	conn         *net.UDPConn // connected child for UDP-LISTEN,fork with reuse
	pc           *net.UDPConn // RECVFROM share, or exclusive listen handoff
	ownsListen   bool         // exclusive UDP-LISTEN,fork,reuseaddr=0
	peer         *net.UDPAddr
	first        []byte
	firstPending bool // buffered opener, including a zero-length datagram
	oneShot      bool
	closed       bool
	env          map[string]string

	writeMu       *sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	releaseListen func()
	wantCtrl      bool
	queued        []udpForkPacket
	g             *xio.Global
	oob           []byte
}

func (u *udpSessionConn) SessionEnvironment() map[string]string { return u.env }

func (u *udpSessionConn) Read(p []byte) (int, error) {
	if u.firstPending {
		u.firstPending = false
		first := u.first
		u.first = nil
		if u.oneShot {
			return copyOneshotFirst(p, first)
		}
		n := copy(p, first)
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	if u.oneShot {
		// UDP-RECVFROM,fork is one-shot: drain first, then EOF.
		return 0, io.EOF
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
		return xio.ZeroLengthMessageEOF(n, nil, len(p))
	}
	n, err := u.conn.Read(p)
	return xio.ZeroLengthMessageEOF(n, err, len(p))
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
			return xio.ZeroLengthMessageEOF(n, nil, len(p))
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
		n, err := u.pc.WriteToUDP(p, u.peer)
		if err == nil {
			return n, nil
		}
		if n2, err2 := u.pc.Write(p); err2 == nil {
			return n2, nil
		}
		return n, err
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

func (u *udpSessionConn) NetConn() net.Conn {
	if u.oneShot {
		// UDP-RECVFROM,fork children share the parent listener.
		return nil
	}
	if u.conn != nil {
		return u.conn
	}
	return u.pc
}

// udpRecvFromConn: first datagram already received; further Read/Write use the
// listening socket with WriteTo to the peer (no rebinding).
// Named field (not embed) so poll does not wait for POLLIN while first is buffered.
type udpRecvFromConn struct {
	uc           *net.UDPConn
	peer         *net.UDPAddr
	first        []byte
	firstPending bool // buffered opener, including a zero-length datagram
	closeEOF     bool // after first payload: further Read → EOF (UDP-RECVFROM one-shot)
	wantCtrl     bool
	g            *xio.Global
	oob          []byte
}

func (u *udpRecvFromConn) Read(p []byte) (int, error) {
	if u.firstPending {
		u.firstPending = false
		first := u.first
		u.first = nil
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
	n, err := u.uc.WriteToUDP(p, u.peer)
	if err == nil {
		return n, nil
	}
	if n2, err2 := u.uc.Write(p); err2 == nil {
		return n2, nil
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
