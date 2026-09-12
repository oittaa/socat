package netopen

import (
	"fmt"
	"net"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

// udpForkAccept is one Accept loop: wait for an opener, then oneshot-share,
// exclusive handoff, or peek-dial reuse.
type udpForkAccept struct {
	l                  *udpForkListener
	pc                 *net.UDPConn
	buf                []byte
	wantCtrl           bool
	recvErr            bool
	peekDial           bool
	oob                [xio.AncillaryBufferSize]byte
	acceptDeadline     time.Time
	failedDialPeer     *net.UDPAddr
	failedDialAttempts int
}

// acceptNext is one Accept-loop iteration: a child, a fatal error, or again
// to keep waiting. again is named here so helpers do not shuffle a boolean
// through different return positions.
type acceptNext struct {
	conn  net.Conn
	err   error
	again bool
}

func acceptAgain() acceptNext         { return acceptNext{again: true} }
func acceptFail(err error) acceptNext { return acceptNext{err: err} }
func acceptChild(c net.Conn, err error) acceptNext {
	return acceptNext{conn: c, err: err}
}

func (n acceptNext) stop() bool { return n.again || n.err != nil }

// udpForkReceive is the opener packet for one loop iteration, including
// idle-timeout retries (again) and receive errors.
type udpForkReceive struct {
	packet   udpForkPacket
	consumed bool
	addr     *net.UDPAddr
	err      error
	again    bool
}

func (r udpForkReceive) next() acceptNext {
	if r.err != nil {
		return acceptFail(r.err)
	}
	if r.again {
		return acceptAgain()
	}
	return acceptNext{}
}

func newUDPForkAccept(l *udpForkListener) (*udpForkAccept, error) {
	if l.pc == nil {
		return nil, net.ErrClosed
	}
	a := &udpForkAccept{
		l:        l,
		pc:       l.pc,
		buf:      make([]byte, 65535),
		wantCtrl: xio.NeedAncillary(l.config),
		recvErr:  xio.NeedRecvErr(l.config),
		peekDial: !l.oneShot && xio.UDPForkPortReuse(l.config) && udpForkUsesPeekDial(),
	}
	if l.acceptTimeout > 0 {
		a.acceptDeadline = time.Now().Add(l.acceptTimeout)
	}
	return a, nil
}

func (l *udpForkListener) Accept() (net.Conn, error) {
	if conn, err, done := l.waitIfHandedOff(); done {
		return conn, err
	}
	a, err := newUDPForkAccept(l)
	if err != nil {
		return nil, err
	}
	for {
		next := a.step()
		if next.again {
			continue
		}
		return next.conn, next.err
	}
}

func (a *udpForkAccept) step() acceptNext {
	a.setReadDeadline()
	got := a.receiveOpener()
	if next := got.next(); next.stop() {
		return next
	}
	if next := a.filterPeer(got.addr, got.consumed); next.stop() {
		return next
	}
	if a.l.oneShot && xio.IgnoreEmptyDatagram(len(got.packet.data), nil, a.l.nullEOF) {
		return acceptAgain()
	}

	session := a.childSession()
	if a.l.oneShot {
		xio.ProcessAncillary(got.packet.oob, session)
		return acceptChild(a.l.newUDPOneshotChild(a.pc, got.packet, session), nil)
	}
	if !xio.UDPForkPortReuse(a.l.config) {
		xio.ProcessAncillary(got.packet.oob, session)
		child := a.l.newUDPForkChild(got.packet, session, a.wantCtrl, a.recvErr)
		return acceptChild(a.l.handoffListenSocket(child))
	}
	if !a.peekDial {
		return acceptFail(fmt.Errorf("UDP fork listener: peek-before-dial unavailable"))
	}
	return a.acceptReuse(got.addr, got.packet, got.consumed, session)
}

func (a *udpForkAccept) setReadDeadline() {
	switch {
	case !a.acceptDeadline.IsZero():
		// Restart the listen accept-timeout after a refused peer.
		_ = a.pc.SetReadDeadline(a.acceptDeadline)
	case a.l.rcvTimeout > 0:
		_ = a.pc.SetReadDeadline(time.Now().Add(a.l.rcvTimeout))
	}
}

func (a *udpForkAccept) receiveOpener() udpForkReceive {
	if a.peekDial && len(a.l.pending) > 0 {
		packet := a.l.pending[0]
		a.l.pending = a.l.pending[1:]
		return udpForkReceive{packet: packet, consumed: true, addr: packet.peer}
	}
	rn, readOOB, addr, err := xio.RecvOneCtx(a.l.ctx, func() (int, []byte, *net.UDPAddr, error) {
		return readUDPForkOpener(a.pc, a.buf, a.wantCtrl, a.oob[:], a.peekDial)
	})
	if err != nil {
		if a.l.ctx.Err() != nil {
			return udpForkReceive{err: err}
		}
		// Keep the listener alive across its periodic receive deadline;
		// continue waiting while idle.
		if a.l.rcvTimeout > 0 && a.acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
			return udpForkReceive{again: true}
		}
		if !a.acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
			return udpForkReceive{err: xio.ErrAcceptTimeout}
		}
		xio.DrainRecvErrOnError(err, a.recvErr, a.pc, a.l.g)
		return udpForkReceive{err: err}
	}
	if !a.peekDial {
		return udpForkReceive{
			packet: udpForkPacket{
				data: append([]byte(nil), a.buf[:rn]...),
				oob:  append([]byte(nil), readOOB...),
				peer: cloneUDPAddr(addr),
			},
			consumed: true,
			addr:     addr,
		}
	}
	return udpForkReceive{addr: addr}
}

func (a *udpForkAccept) filterPeer(addr *net.UDPAddr, consumed bool) acceptNext {
	if err := a.l.peerAllowed(addr); err != nil {
		if a.peekDial && !consumed {
			// The opener was only peeked. Consume the refused datagram or the
			// next loop would inspect the same peer forever.
			if _, _, _, dropErr := xio.ReadUDPMsgWithBuffer(a.pc, a.buf, false, nil); dropErr != nil {
				xio.DrainRecvErrOnError(dropErr, a.recvErr, a.pc, a.l.g)
				return acceptFail(dropErr)
			}
		}
		if stop := logOrStopPeerFilter(a.l.ctx, a.l.g, err); stop != nil {
			return acceptFail(stop)
		}
		// Restart the listen accept-timeout after a refused peer.
		if a.l.acceptTimeout > 0 {
			a.acceptDeadline = time.Now().Add(a.l.acceptTimeout)
		}
		return acceptAgain()
	}
	return acceptNext{}
}

func (a *udpForkAccept) childSession() *xio.Global {
	return a.l.g.ForkSession()
}

func (a *udpForkAccept) acceptReuse(addr *net.UDPAddr, packet udpForkPacket, consumed bool, session *xio.Global) acceptNext {
	local := a.l.laddr
	if la, ok := a.pc.LocalAddr().(*net.UDPAddr); ok {
		local = cloneUDPAddr(la)
	}
	conn, err := dialUDPSession(a.l.ctx, a.l.network, local, addr, a.l.config)
	if err != nil {
		return a.noteDialFailure(addr, packet, consumed, err)
	}
	a.failedDialPeer = nil
	a.failedDialAttempts = 0

	got := a.consumePeekedOpener(conn, addr, packet, consumed)
	if next := got.next(); next.stop() {
		return next
	}

	xio.ProcessAncillary(got.packet.oob, session)
	child := a.l.newUDPForkChild(got.packet, session, a.wantCtrl, a.recvErr)
	child.setConnected(conn)
	a.drainForChild(child)
	return acceptChild(child, nil)
}

func (a *udpForkAccept) noteDialFailure(addr *net.UDPAddr, packet udpForkPacket, consumed bool, dialErr error) acceptNext {
	if udpAddrIsPeer(addr, a.failedDialPeer) {
		a.failedDialAttempts++
	} else {
		a.failedDialPeer = cloneUDPAddr(addr)
		a.failedDialAttempts = 1
	}
	if a.failedDialAttempts < udpForkDialMaxAttempts {
		if consumed {
			a.l.prependPending(packet)
		}
		if a.l.g != nil && a.l.g.Log != nil {
			a.l.g.Log.Noticef("UDP fork session dial: %s; retrying opener", dialErr)
		}
		return acceptAgain()
	}
	if !consumed {
		// Remove the opener that MSG_PEEK left on the socket. Preserve an
		// unexpected packet rather than dropping a different peer.
		n, dropOOB, peer, ok, dropErr := readQueuedUDPForkPacket(a.pc, a.buf, a.wantCtrl, a.oob[:])
		if dropErr != nil {
			xio.DrainRecvErrOnError(dropErr, a.recvErr, a.pc, a.l.g)
			return acceptFail(dropErr)
		}
		if ok && !udpAddrIsPeer(peer, addr) {
			a.l.appendPending(udpForkPacket{
				data: append([]byte(nil), a.buf[:n]...),
				oob:  append([]byte(nil), dropOOB...),
				peer: cloneUDPAddr(peer),
			})
		}
	}
	if a.l.g != nil && a.l.g.Log != nil {
		a.l.g.Log.Noticef("UDP fork session dial: %s; dropping opener after %d attempts", dialErr, a.failedDialAttempts)
	}
	a.failedDialPeer = nil
	a.failedDialAttempts = 0
	return acceptAgain()
}

func (a *udpForkAccept) consumePeekedOpener(conn net.Conn, addr *net.UDPAddr, packet udpForkPacket, consumed bool) udpForkReceive {
	if consumed {
		return udpForkReceive{packet: packet}
	}
	rn, oob, peer, ok, err := readQueuedUDPForkPacket(a.pc, a.buf, a.wantCtrl, a.oob[:])
	if err != nil {
		xio.DrainRecvErrOnError(err, a.recvErr, a.pc, a.l.g)
		logx.CloseQuiet(conn)
		return udpForkReceive{err: err}
	}
	if !ok {
		logx.CloseQuiet(conn)
		if a.l.g != nil && a.l.g.Log != nil {
			a.l.g.Log.Noticef("UDP fork opener disappeared before session handoff")
		}
		return udpForkReceive{again: true}
	}
	packet = udpForkPacket{
		data: append([]byte(nil), a.buf[:rn]...),
		oob:  append([]byte(nil), oob...),
		peer: cloneUDPAddr(peer),
	}
	if !udpAddrIsPeer(packet.peer, addr) {
		logx.CloseQuiet(conn)
		a.l.appendPending(packet)
		if a.l.g != nil && a.l.g.Log != nil {
			a.l.g.Log.Noticef("UDP fork opener changed from %s to %s; preserving received packet", addr, packet.peer)
		}
		return udpForkReceive{again: true}
	}
	return udpForkReceive{packet: packet}
}

func (a *udpForkAccept) drainForChild(child *udpSessionConn) {
	if len(a.l.pending) > 0 {
		remaining := make([]udpForkPacket, 0, len(a.l.pending))
		for _, queued := range a.l.pending {
			if udpAddrIsPeer(queued.peer, child.peer) {
				appendUDPForkSessionPacket(child, queued)
			} else {
				remaining = append(remaining, queued)
			}
		}
		a.l.pending = remaining
	}
	for range udpForkDrainPacketLimit {
		n, queuedOOB, peer, ok, drainErr := readQueuedUDPForkPacket(a.pc, a.buf, a.wantCtrl, a.oob[:])
		if drainErr != nil {
			xio.DrainRecvErrOnError(drainErr, a.recvErr, a.pc, a.l.g)
			if a.l.g != nil && a.l.g.Log != nil {
				a.l.g.Log.Noticef("UDP fork listener queue drain: %s", drainErr)
			}
			break
		}
		if !ok {
			break
		}
		queued := udpForkPacket{
			data: append([]byte(nil), a.buf[:n]...),
			oob:  append([]byte(nil), queuedOOB...),
			peer: cloneUDPAddr(peer),
		}
		if udpAddrIsPeer(peer, child.peer) {
			appendUDPForkSessionPacket(child, queued)
		} else {
			a.l.appendPending(queued)
		}
	}
}
