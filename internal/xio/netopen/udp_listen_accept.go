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

func newUDPForkAccept(l *udpForkListener) (*udpForkAccept, error) {
	if l.pc == nil {
		return nil, net.ErrClosed
	}
	a := &udpForkAccept{
		l:        l,
		pc:       l.pc,
		buf:      make([]byte, 65535),
		wantCtrl: xio.NeedAncillary(l.spec),
		recvErr:  xio.NeedRecvErr(l.spec),
		peekDial: !l.oneShot && xio.UDPForkPortReuse(l.spec) && udpForkUsesPeekDial(),
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
		conn, err, again := a.step()
		if !again {
			return conn, err
		}
	}
}

func (a *udpForkAccept) step() (net.Conn, error, bool) {
	a.setReadDeadline()
	packet, consumed, addr, err, again := a.receiveOpener()
	if err != nil {
		return nil, err, false
	}
	if again {
		return nil, nil, true
	}
	again, err = a.filterPeer(addr, consumed)
	if err != nil {
		return nil, err, false
	}
	if again {
		return nil, nil, true
	}
	if a.l.oneShot && xio.IgnoreEmptyDatagram(len(packet.data), nil, a.l.spec.BoolOption("null-eof")) {
		return nil, nil, true
	}

	session := a.childSession()
	if a.l.oneShot {
		xio.ProcessAncillary(packet.oob, session)
		child := a.l.newUDPForkChild(packet, session, a.wantCtrl, a.recvErr)
		// Share the parent socket (one-shot). A
		// connected child on the same port would steal later datagrams.
		child.setShared(a.pc)
		return child, nil, false
	}
	if !xio.UDPForkPortReuse(a.l.spec) {
		xio.ProcessAncillary(packet.oob, session)
		child := a.l.newUDPForkChild(packet, session, a.wantCtrl, a.recvErr)
		conn, err := a.l.handoffListenSocket(child)
		return conn, err, false
	}
	if !a.peekDial {
		return nil, fmt.Errorf("UDP fork listener: peek-before-dial unavailable"), false
	}
	return a.acceptReuse(addr, packet, consumed, session)
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

func (a *udpForkAccept) receiveOpener() (packet udpForkPacket, consumed bool, addr *net.UDPAddr, err error, again bool) {
	if a.peekDial && len(a.l.pending) > 0 {
		packet = a.l.pending[0]
		a.l.pending = a.l.pending[1:]
		return packet, true, packet.peer, nil, false
	}
	var rn int
	var readOOB []byte
	rn, readOOB, addr, err = xio.RecvOneCtx(a.l.ctx, func() (int, []byte, *net.UDPAddr, error) {
		return readUDPForkOpener(a.pc, a.buf, a.wantCtrl, a.oob[:], a.peekDial)
	})
	if err != nil {
		if a.l.ctx.Err() != nil {
			return udpForkPacket{}, false, nil, err, false
		}
		// Keep the listener alive across its periodic receive deadline;
		// continue waiting while idle.
		if a.l.rcvTimeout > 0 && a.acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
			return udpForkPacket{}, false, nil, nil, true
		}
		if !a.acceptDeadline.IsZero() && xio.IsTimeoutErr(err) {
			return udpForkPacket{}, false, nil, xio.ErrAcceptTimeout, false
		}
		xio.DrainRecvErrOnError(err, a.recvErr, a.pc, a.l.g)
		return udpForkPacket{}, false, nil, err, false
	}
	if !a.peekDial {
		packet = udpForkPacket{
			data: append([]byte(nil), a.buf[:rn]...),
			oob:  append([]byte(nil), readOOB...),
			peer: cloneUDPAddr(addr),
		}
		return packet, true, addr, nil, false
	}
	return udpForkPacket{}, false, addr, nil, false
}

func (a *udpForkAccept) filterPeer(addr *net.UDPAddr, consumed bool) (again bool, err error) {
	if err := a.l.peerAllowed(addr); err != nil {
		if a.peekDial && !consumed {
			// The opener was only peeked. Consume the refused datagram or the
			// next loop would inspect the same peer forever.
			if _, _, _, dropErr := xio.ReadUDPMsgWithBuffer(a.pc, a.buf, false, nil); dropErr != nil {
				xio.DrainRecvErrOnError(dropErr, a.recvErr, a.pc, a.l.g)
				return false, dropErr
			}
		}
		if stop := logOrStopPeerFilter(a.l.ctx, a.l.g, err); stop != nil {
			return false, stop
		}
		// Restart the listen accept-timeout after a refused peer.
		if a.l.acceptTimeout > 0 {
			a.acceptDeadline = time.Now().Add(a.l.acceptTimeout)
		}
		return true, nil
	}
	return false, nil
}

func (a *udpForkAccept) childSession() *xio.Global {
	session := &xio.Global{}
	if a.l.g != nil {
		session.Log = a.l.g.Log
		session.Progname = a.l.g.Progname
	}
	return session
}

func (a *udpForkAccept) acceptReuse(addr *net.UDPAddr, packet udpForkPacket, consumed bool, session *xio.Global) (net.Conn, error, bool) {
	local := a.l.laddr
	if la, ok := a.pc.LocalAddr().(*net.UDPAddr); ok {
		local = cloneUDPAddr(la)
	}
	conn, err := dialUDPSession(a.l.ctx, a.l.network, local, addr, a.l.spec)
	if err != nil {
		again, derr := a.noteDialFailure(addr, packet, consumed, err)
		if derr != nil {
			return nil, derr, false
		}
		return nil, nil, again
	}
	a.failedDialPeer = nil
	a.failedDialAttempts = 0

	packet, err, again := a.consumePeekedOpener(conn, addr, packet, consumed)
	if err != nil {
		return nil, err, false
	}
	if again {
		return nil, nil, true
	}

	xio.ProcessAncillary(packet.oob, session)
	child := a.l.newUDPForkChild(packet, session, a.wantCtrl, a.recvErr)
	child.setConnected(conn)
	a.drainForChild(child)
	return child, nil, false
}

func (a *udpForkAccept) noteDialFailure(addr *net.UDPAddr, packet udpForkPacket, consumed bool, dialErr error) (again bool, err error) {
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
		return true, nil
	}
	if !consumed {
		// Remove the opener that MSG_PEEK left on the socket. Preserve an
		// unexpected packet rather than dropping a different peer.
		n, dropOOB, peer, ok, dropErr := readQueuedUDPForkPacket(a.pc, a.buf, a.wantCtrl, a.oob[:])
		if dropErr != nil {
			xio.DrainRecvErrOnError(dropErr, a.recvErr, a.pc, a.l.g)
			return false, dropErr
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
	return true, nil
}

func (a *udpForkAccept) consumePeekedOpener(conn net.Conn, addr *net.UDPAddr, packet udpForkPacket, consumed bool) (udpForkPacket, error, bool) {
	if consumed {
		return packet, nil, false
	}
	rn, oob, peer, ok, err := readQueuedUDPForkPacket(a.pc, a.buf, a.wantCtrl, a.oob[:])
	if err != nil {
		xio.DrainRecvErrOnError(err, a.recvErr, a.pc, a.l.g)
		logx.CloseQuiet(conn)
		return udpForkPacket{}, err, false
	}
	if !ok {
		logx.CloseQuiet(conn)
		if a.l.g != nil && a.l.g.Log != nil {
			a.l.g.Log.Noticef("UDP fork opener disappeared before session handoff")
		}
		return udpForkPacket{}, nil, true
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
		return udpForkPacket{}, nil, true
	}
	return packet, nil, false
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
