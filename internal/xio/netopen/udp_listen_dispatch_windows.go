//go:build windows

package netopen

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

// Windows documents delivery between SO_REUSEADDR sockets as indeterminate.
// Keep one socket responsible for receiving and demultiplex packets by peer in
// user space so UDP-LISTEN,fork keeps per-peer sessions.
const (
	udpDispatchAcceptQueueSize = 256
	udpDispatchPacketQueueSize = 64
)

type udpDispatchListener struct {
	base *udpForkListener

	accepts     chan net.Conn
	done        chan struct{}
	once        sync.Once
	closeErr    error
	terminalErr error

	mu       sync.Mutex
	sessions map[string]*udpDispatchConn
	writeMu  sync.Mutex

	// peerRejected is a coalesced signal that Accept should restart
	// accept-timeout after a refused peer (same as TCP listen).
	peerRejected chan struct{}
}

func udpForkSharesListenSocket() bool { return true }

func newUDPListenForkListener(base *udpForkListener) net.Listener {
	l := &udpDispatchListener{
		base:         base,
		accepts:      make(chan net.Conn, udpDispatchAcceptQueueSize),
		done:         make(chan struct{}),
		sessions:     make(map[string]*udpDispatchConn),
		peerRejected: make(chan struct{}, 1),
	}
	go l.readLoop()
	go func() {
		select {
		case <-base.ctx.Done():
			_ = l.Close()
		case <-l.done:
		}
	}()
	return l
}

func (l *udpDispatchListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.base.ctx.Done():
			return nil, l.base.ctx.Err()
		case <-l.done:
			return nil, l.closedError()
		default:
		}

		var timer *time.Timer
		var timeout <-chan time.Time
		if l.base.acceptTimeout > 0 {
			timer = time.NewTimer(l.base.acceptTimeout)
			timeout = timer.C
		}

		select {
		case conn := <-l.accepts:
			stopUDPDispatchTimer(timer)
			select {
			case <-l.done:
				_ = conn.Close()
				return nil, l.closedError()
			default:
			}
			return conn, nil
		case <-timeout:
			stopUDPDispatchTimer(timer)
			select {
			case conn := <-l.accepts:
				return conn, nil
			default:
			}
			// A refused packet and the timer can become ready together. Give
			// the packet the same timeout-reset semantics as when its signal
			// wins the outer select.
			select {
			case <-l.peerRejected:
				continue
			default:
				return nil, xio.ErrAcceptTimeout
			}
		case <-l.peerRejected:
			stopUDPDispatchTimer(timer)
			continue
		case <-l.base.ctx.Done():
			stopUDPDispatchTimer(timer)
			return nil, l.base.ctx.Err()
		case <-l.done:
			stopUDPDispatchTimer(timer)
			return nil, l.closedError()
		}
	}
}

func (l *udpDispatchListener) closedError() error {
	if l.terminalErr != nil {
		return l.terminalErr
	}
	return net.ErrClosed
}

func (l *udpDispatchListener) Close() error {
	return l.shutdown(nil)
}

func (l *udpDispatchListener) shutdown(cause error) error {
	l.once.Do(func() {
		l.terminalErr = cause
		close(l.done)
		l.closeErr = l.base.pc.Close()

		l.mu.Lock()
		children := make([]*udpDispatchConn, 0, len(l.sessions))
		for _, child := range l.sessions {
			children = append(children, child)
		}
		clear(l.sessions)
		l.mu.Unlock()
		for _, child := range children {
			child.closeFromListener()
		}
		for {
			select {
			case conn := <-l.accepts:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return l.closeErr
}

func (l *udpDispatchListener) Addr() net.Addr  { return l.base.pc.LocalAddr() }
func (*udpDispatchListener) oneShotMode() bool { return false }

func (l *udpDispatchListener) readLoop() {
	buf := make([]byte, 65535)
	wantCtrl := xio.NeedAncillary(l.base.spec)
	var oobBuffer [xio.AncillaryBufferSize]byte
	for {
		if l.base.rcvTimeout > 0 {
			_ = l.base.pc.SetReadDeadline(time.Now().Add(l.base.rcvTimeout))
		}
		rn, oob, peer, err := xio.ReadUDPMsgWithBuffer(l.base.pc, buf, wantCtrl, oobBuffer[:])
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if l.base.rcvTimeout > 0 && xio.IsTimeoutErr(err) {
				continue
			}
			_ = l.shutdown(err)
			return
		}
		if err := l.base.peerAllowed(peer); err != nil {
			if stop := logOrStopPeerFilter(l.base.ctx, l.base.g, err); stop != nil {
				_ = l.shutdown(stop)
				return
			}
			select {
			case l.peerRejected <- struct{}{}:
			default:
			}
			continue
		}

		packet := append([]byte(nil), buf[:rn]...)
		key := peer.String()
		l.mu.Lock()
		child := l.sessions[key]
		l.mu.Unlock()
		if child != nil && child.enqueue(packet) {
			continue
		}

		session := &xio.Global{}
		if l.base.g != nil {
			session.Log = l.base.g.Log
			session.Progname = l.base.g.Progname
		}
		xio.ProcessAncillary(oob, session)
		child = &udpDispatchConn{
			listener:        l,
			pc:              l.base.pc,
			peer:            cloneUDPAddr(peer),
			key:             key,
			pending:         packet,
			havePending:     true,
			packets:         make(chan []byte, udpDispatchPacketQueueSize),
			done:            make(chan struct{}),
			deadlineChanged: make(chan struct{}, 1),
			env:             session.SessionVars,
		}
		l.mu.Lock()
		select {
		case <-l.done:
			l.mu.Unlock()
			_ = child.Close()
			return
		default:
			l.sessions[key] = child
			l.mu.Unlock()
		}

		select {
		case l.accepts <- child:
		case <-l.done:
			_ = child.Close()
			return
		default:
			// UDP permits loss under overload. Do not let an unaccepted new
			// peer block delivery to established sessions.
			_ = child.Close()
		}
	}
}

func (l *udpDispatchListener) remove(key string, child *udpDispatchConn) {
	l.mu.Lock()
	if l.sessions[key] == child {
		delete(l.sessions, key)
	}
	l.mu.Unlock()
}

type udpDispatchConn struct {
	listener *udpDispatchListener
	pc       *net.UDPConn
	peer     *net.UDPAddr
	key      string
	env      map[string]string

	readMu      sync.Mutex
	pending     []byte
	havePending bool
	packets     chan []byte
	done        chan struct{}
	closeOnce   sync.Once

	deadlineMu      sync.Mutex
	readDeadline    time.Time
	writeDeadline   time.Time
	deadlineChanged chan struct{}
}

func (c *udpDispatchConn) SessionEnvironment() map[string]string { return c.env }

func (c *udpDispatchConn) enqueue(packet []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.packets <- packet:
	case <-c.done:
		return false
	default:
		// Match UDP socket-buffer overflow: drop this packet but keep the
		// established peer session and continue receiving other peers.
	}
	return true
}

func (c *udpDispatchConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.havePending {
			n := copy(p, c.pending)
			c.pending = nil
			c.havePending = false
			return n, nil
		}
		packet, err := c.waitPacket()
		if err != nil {
			return 0, err
		}
		c.pending = packet
		c.havePending = true
	}
}

func (c *udpDispatchConn) waitPacket() ([]byte, error) {
	for {
		c.deadlineMu.Lock()
		deadline := c.readDeadline
		c.deadlineMu.Unlock()

		if deadline.IsZero() {
			select {
			case packet := <-c.packets:
				return packet, nil
			case <-c.deadlineChanged:
				continue
			case <-c.done:
				return nil, net.ErrClosed
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case packet := <-c.packets:
			stopUDPDispatchTimer(timer)
			return packet, nil
		case <-c.deadlineChanged:
			stopUDPDispatchTimer(timer)
			continue
		case <-c.done:
			stopUDPDispatchTimer(timer)
			return nil, net.ErrClosed
		case <-timer.C:
			return nil, os.ErrDeadlineExceeded
		}
	}
}

func stopUDPDispatchTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (c *udpDispatchConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	return writeSharedPacket(&c.listener.writeMu, deadline, c.pc.SetWriteDeadline, func() (int, error) {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		default:
		}
		return c.pc.WriteToUDP(p, c.peer)
	})
}

func (c *udpDispatchConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.listener.remove(c.key, c)
		select {
		case c.deadlineChanged <- struct{}{}:
		default:
		}
	})
	return nil
}

func (c *udpDispatchConn) closeFromListener() {
	c.closeOnce.Do(func() {
		close(c.done)
		select {
		case c.deadlineChanged <- struct{}{}:
		default:
		}
	})
}

func (c *udpDispatchConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *udpDispatchConn) RemoteAddr() net.Addr { return c.peer }

func (c *udpDispatchConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *udpDispatchConn) SetReadDeadline(t time.Time) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (c *udpDispatchConn) SetWriteDeadline(t time.Time) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}
