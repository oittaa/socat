package dtls13

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing/synctest"
	"time"
)

// Channel I/O lets synctest advance the actual connection timers deterministically.
type handshakePacketConn struct {
	addr     netip.AddrPort
	incoming chan incomingPacket
	closed   chan struct{}
	once     sync.Once
	send     func([]byte, netip.AddrPort)
}

func newHandshakePacketConn(port uint16) *handshakePacketConn {
	return &handshakePacketConn{addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
		incoming: make(chan incomingPacket, 256), closed: make(chan struct{})}
}

func (p *handshakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case packet := <-p.incoming:
		return copy(b, packet.data), net.UDPAddrFromAddrPort(packet.peer), nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	}
}

func (p *handshakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	peer, err := udpAddress(addr)
	if err != nil {
		return 0, err
	}
	if p.send != nil {
		p.send(bytes.Clone(b), peer)
	}
	return len(b), nil
}

func (p *handshakePacketConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *handshakePacketConn) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(p.addr) }
func (p *handshakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (p *handshakePacketConn) SetReadDeadline(time.Time) error {
	return errors.New("association timeout must not set the transport read deadline")
}
func (p *handshakePacketConn) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

func advanceHandshakeClock(d time.Duration) {
	<-time.After(d)
	synctest.Wait()
}
