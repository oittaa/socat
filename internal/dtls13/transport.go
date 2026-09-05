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
	data     []byte
	peer     netip.AddrPort
	deadline time.Time
	cancel   <-chan struct{}
	result   chan error
}

// One writer owns socket deadlines even when associations share a UDP socket.
type packetTransport struct {
	conn    net.PacketConn
	writes  chan packetWrite
	done    chan struct{}
	once    sync.Once
	receive func([]byte, netip.AddrPort)
	failed  func(error)
}

func newPacketTransport(conn net.PacketConn, receive func([]byte, netip.AddrPort), failed func(error)) *packetTransport {
	return &packetTransport{conn: conn, writes: make(chan packetWrite, 16), done: make(chan struct{}), receive: receive, failed: failed}
}

func (p *packetTransport) start() {
	go p.readLoop()
	go p.writeLoop()
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
		n, from, err := p.conn.ReadFrom(buffer)
		if err != nil {
			p.close(err)
			return
		}
		peer, err := udpAddress(from)
		if err == nil && n != 0 {
			p.receive(buffer[:n], peer)
		}
	}
}

func (p *packetTransport) writeLoop() {
	for {
		select {
		case <-p.done:
			return
		case w := <-p.writes:
			select {
			case <-w.cancel:
				continue
			default:
			}
			if !time.Now().Before(w.deadline) {
				w.result <- os.ErrDeadlineExceeded
				continue
			}
			err := p.conn.SetWriteDeadline(w.deadline)
			if err == nil {
				var n int
				n, err = p.conn.WriteTo(w.data, net.UDPAddrFromAddrPort(w.peer))
				if err == nil && n != len(w.data) {
					err = io.ErrShortWrite
				}
			}
			w.result <- err
		}
	}
}

func (p *packetTransport) write(data []byte, peer netip.AddrPort, deadline time.Time, stopped <-chan struct{}) error {
	// Bound control writes as well as application writes on congested sockets.
	limit := time.Now().Add(time.Second)
	if deadline.IsZero() || limit.Before(deadline) {
		deadline = limit
	}
	if !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	cancel := make(chan struct{})
	defer close(cancel)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	w := packetWrite{data: data, peer: peer, deadline: deadline, cancel: cancel, result: make(chan error, 1)}
	select {
	case p.writes <- w:
	case <-p.done:
		return net.ErrClosed
	case <-stopped:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
	select {
	case err := <-w.result:
		return err
	case <-p.done:
		return net.ErrClosed
	case <-stopped:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}
