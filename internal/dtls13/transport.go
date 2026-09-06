package dtls13

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

type packetWrite struct {
	data      []byte
	peer      netip.AddrPort
	deadline  time.Time
	cancel    <-chan struct{}
	stopped   <-chan struct{}
	cancelled <-chan struct{}
	result    chan error
	retry     bool
}

var errWritePending = errors.New("dtls: datagram write still pending")

func (w packetWrite) timeout() error {
	if w.retry {
		return errWritePending
	}
	return os.ErrDeadlineExceeded
}

// One writer owns socket deadlines even when associations share a UDP socket.
type packetTransport struct {
	conn    net.PacketConn
	udp     *net.UDPConn
	direct  bool // A client session is the only sender on its socket.
	writes  chan packetWrite
	done    chan struct{}
	once    sync.Once
	receive func([]byte, netip.AddrPort)
	failed  func(error)

	writeMu sync.Mutex
	active  [3]<-chan struct{}
}

func newPacketTransport(conn net.PacketConn, receive func([]byte, netip.AddrPort), failed func(error)) *packetTransport {
	udp, _ := conn.(*net.UDPConn)
	return &packetTransport{
		conn: conn, udp: udp, writes: make(chan packetWrite, 16), done: make(chan struct{}), receive: receive, failed: failed,
	}
}

func (p *packetTransport) start() {
	go p.readLoop()
	if !p.direct {
		go p.writeLoop()
	}
}

func (p *packetTransport) close(err error) {
	closed := false
	p.once.Do(func() {
		closed = true
		close(p.done)
		_ = p.conn.Close()
	})
	if closed && p.failed != nil {
		p.failed(err)
	}
}

func udpAddress(addr net.Addr) (netip.AddrPort, error) {
	a, ok := addr.(*net.UDPAddr)
	if !ok || a == nil {
		return netip.AddrPort{}, errors.New("dtls: UDP address required")
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok || a.Port < 0 || a.Port > 65535 {
		return netip.AddrPort{}, errors.New("dtls: invalid UDP address")
	}
	if a.Zone != "" {
		ip = ip.WithZone(a.Zone)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), nil
}

func (p *packetTransport) readLoop() {
	buffer := make([]byte, 65535)
	for {
		var n int
		var peer netip.AddrPort
		var err error
		if p.udp != nil {
			n, peer, err = p.udp.ReadFromUDPAddrPort(buffer)
			peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		} else {
			var from net.Addr
			n, from, err = p.conn.ReadFrom(buffer)
			if err == nil {
				var addressErr error
				peer, addressErr = udpAddress(from)
				if addressErr != nil {
					continue
				}
			}
		}
		if err != nil {
			p.close(err)
			return
		}
		if n != 0 {
			p.receive(buffer[:n], peer)
		}
	}
}

func (p *packetTransport) writeTo(data []byte, peer netip.AddrPort) (int, error) {
	if p.udp != nil {
		return p.udp.WriteToUDPAddrPort(data, peer)
	}
	return p.conn.WriteTo(data, net.UDPAddrFromAddrPort(peer))
}

func (p *packetTransport) writeLoop() {
	for {
		select {
		case <-p.done:
			return
		case w := <-p.writes:
			w.result <- p.writeNow(w)
		}
	}
}

func (p *packetTransport) startWrite(w packetWrite) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	case <-w.cancel:
		return net.ErrClosed
	case <-w.stopped:
		return net.ErrClosed
	case <-w.cancelled:
		return net.ErrClosed
	default:
	}
	if !time.Now().Before(w.deadline) {
		return w.timeout()
	}
	if err := p.conn.SetWriteDeadline(w.deadline); err != nil {
		return err
	}
	p.active = [3]<-chan struct{}{w.cancel, w.stopped, w.cancelled}
	return nil
}

func (p *packetTransport) writeNow(w packetWrite) error {
	if err := p.startWrite(w); err != nil {
		return err
	}
	n, err := p.writeTo(w.data, w.peer)
	p.writeMu.Lock()
	p.active = [3]<-chan struct{}{}
	p.writeMu.Unlock()
	if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
		return w.timeout()
	}
	if err == nil && n != len(w.data) {
		return io.ErrShortWrite
	}
	return err
}

// Cancellation and deadline installation share a lock so a late cancellation
// cannot interrupt the next association's socket write.
func (p *packetTransport) cancelWrite(signal chan struct{}) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	close(signal)
	for _, active := range p.active {
		if active == signal {
			_ = p.conn.SetWriteDeadline(time.Now())
			break
		}
	}
}

func (p *packetTransport) write(data []byte, peer netip.AddrPort, deadline time.Time, stopped <-chan struct{}) error {
	return p.writePacket(data, peer, deadline, stopped, nil, false)
}

func (p *packetTransport) writeApplication(data []byte, peer netip.AddrPort, deadline time.Time, stopped, cancelled <-chan struct{}) error {
	return p.writePacket(data, peer, deadline, stopped, cancelled, true)
}

func (p *packetTransport) writePacket(data []byte, peer netip.AddrPort, deadline time.Time, stopped, cancelled <-chan struct{}, retry bool) error {
	// Bound each socket attempt so other associations and protocol timers run.
	limit := time.Now().Add(time.Second)
	if deadline.IsZero() || limit.Before(deadline) {
		deadline = limit
	}
	if p.direct {
		return p.writeNow(packetWrite{data: data, peer: peer, deadline: deadline,
			stopped: stopped, cancelled: cancelled, retry: retry})
	}
	cancel := make(chan struct{})
	defer p.cancelWrite(cancel)
	w := packetWrite{data: data, peer: peer, deadline: deadline, cancel: cancel,
		stopped: stopped, cancelled: cancelled, result: make(chan error, 1), retry: retry}
	if !time.Now().Before(deadline) {
		return w.timeout()
	}
	if retry {
		select {
		case p.writes <- w:
			return p.waitWrite(w, nil)
		default:
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case p.writes <- w:
	case <-p.done:
		return net.ErrClosed
	case <-stopped:
		return net.ErrClosed
	case <-cancelled:
		return net.ErrClosed
	case <-timer.C:
		return w.timeout()
	}
	timeout := timer.C
	if retry {
		// Once queued, only the writer can establish that no bytes were sent.
		timer.Stop()
		timeout = nil
	}
	return p.waitWrite(w, timeout)
}

func (p *packetTransport) waitWrite(w packetWrite, timeout <-chan time.Time) error {
	select {
	case err := <-w.result:
		return err
	case <-p.done:
		return net.ErrClosed
	case <-w.stopped:
		return net.ErrClosed
	case <-w.cancelled:
		return net.ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}
