package dtls13

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type gatedWriteConn struct {
	*handshakePacketConn
	gate     <-chan struct{}
	mu       sync.Mutex
	deadline time.Time
	notify   chan struct{}
	attempts int
	n        int
	err      error
}

func (p *gatedWriteConn) SetWriteDeadline(deadline time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = deadline
	if p.notify != nil {
		close(p.notify)
	}
	p.notify = make(chan struct{})
	return nil
}

func (p *gatedWriteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.attempts++
	if p.gate != nil {
		for {
			p.mu.Lock()
			deadline, notify := p.deadline, p.notify
			p.mu.Unlock()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return p.n, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(time.Until(deadline))
			select {
			case <-p.gate:
				timer.Stop()
				return p.handshakePacketConn.WriteTo(b, addr)
			case <-timer.C:
				return p.n, os.ErrDeadlineExceeded
			case <-p.closed:
				timer.Stop()
				return 0, net.ErrClosed
			case <-notify:
				timer.Stop()
			}
		}
	}
	if p.err != nil {
		if p.n == -1 {
			return len(b), p.err
		}
		return p.n, p.err
	}
	return p.handshakePacketConn.WriteTo(b, addr)
}

func TestConnFailureInterruptsApplicationWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, _, p := syntheticConnectionPair(t)
		p.gate = make(chan struct{})
		result := make(chan error, 1)
		go func() { _, err := client.Write([]byte("blocked")); result <- err }()
		synctest.Wait()
		started := time.Now()
		client.fail(errUnexpectedMessage)
		if err := <-result; !errors.Is(err, errUnexpectedMessage) {
			t.Fatalf("interrupted write: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed != 0 {
			t.Fatalf("shutdown waited for the socket deadline: %v", elapsed)
		}
	})
}

func TestTransportFullWriteQueueDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newHandshakePacketConn(10001)
		transport := newPacketTransport(p, nil, nil)
		defer transport.close(net.ErrClosed)
		// A stalled writer leaves no queue capacity for this operation.
		for range cap(transport.writes) {
			transport.writes <- packetWrite{}
		}
		started := time.Now()
		deadline := started.Add(250 * time.Millisecond)
		err := transport.writeApplication([]byte("queued"), p.addr, deadline, nil, nil)
		if !errors.Is(err, errWritePending) || time.Since(started) != 250*time.Millisecond {
			t.Fatalf("full queue: %v after %v", err, time.Since(started))
		}
	})
}

// Call within synctest; its barriers also synchronize the fake socket controls.
func syntheticConnectionPair(t *testing.T) (*Conn, *Conn, *gatedWriteConn) {
	t.Helper()
	a, b := handshakeConfigs(t)
	a.CurvePreferences, b.CurvePreferences = []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519}
	cp := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001)}
	sp := newHandshakePacketConn(10002)
	cp.send = func(data []byte, _ netip.AddrPort) { sp.incoming <- incomingPacket{data, cp.addr} }
	sp.send = func(data []byte, _ netip.AddrPort) { cp.incoming <- incomingPacket{data, sp.addr} }
	listener, err := Listen(sp, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := Client(context.Background(), cp, listener.Addr(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := listener.AcceptContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server := accepted.(*Conn)
	synctest.Wait()
	for step := 0; ; step++ {
		if client.session.outbound.complete && len(client.session.post) == 0 && len(server.session.post) == 0 &&
			client.session.ackDeadline.IsZero() && server.session.ackDeadline.IsZero() {
			break
		}
		if step == 20 {
			t.Fatal("initial post-handshake flights did not settle")
		}
		advanceHandshakeClock(initialRetransmit / 4)
	}
	return client, server, cp
}
