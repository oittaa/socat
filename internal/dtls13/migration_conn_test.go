package dtls13

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// rebindTransport models a NAT mapping change while retaining DTLS state.
type rebindTransport struct {
	mu sync.Mutex
	net.PacketConn
	writeDeadline time.Time
}

func (r *rebindTransport) replace(next net.PacketConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := next.SetWriteDeadline(r.writeDeadline); err != nil {
		return err
	}
	previous := r.PacketConn
	r.PacketConn = next
	return previous.Close()
}

func (r *rebindTransport) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		r.mu.Lock()
		current := r.PacketConn
		r.mu.Unlock()
		n, addr, err := current.ReadFrom(data)
		r.mu.Lock()
		replaced := current != r.PacketConn
		r.mu.Unlock()
		if replaced {
			continue
		}
		return n, addr, err
	}
}

func (r *rebindTransport) WriteTo(data []byte, peer net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.WriteTo(data, peer)
}

func (r *rebindTransport) SetWriteDeadline(deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeDeadline = deadline
	return r.PacketConn.SetWriteDeadline(deadline)
}

func (r *rebindTransport) LocalAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.LocalAddr()
}

func (r *rebindTransport) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.Close()
}

func TestConnMigratesAfterEnhancedReturnRoutability(t *testing.T) {
	a, b := handshakeConfigs(t)
	listener, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport := &rebindTransport{PacketConn: testUDP(t)}
	client, err := Client(ctx, transport, listener.Addr(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.RotateConnectionID(); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateKeys(true); err != nil {
		t.Fatal(err)
	}
	previous := server.RemoteAddr().String()
	if err := transport.replace(testUDP(t)); err != nil {
		t.Fatal(err)
	}
	if previous == transport.LocalAddr().String() {
		t.Fatal("test did not change the UDP port")
	}
	if _, err := client.Write([]byte("rebound")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := server.Read(buffer)
	if err != nil || string(buffer[:n]) != "rebound" {
		t.Fatalf("migrated read = %q, %v", buffer[:n], err)
	}
	// The response waits for the old-path timeout and new-path challenge.
	if _, err := server.Write(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buffer)
	if err != nil || string(buffer[:n]) != "rebound" {
		t.Fatalf("migrated response = %q, %v", buffer[:n], err)
	}
	if got := server.RemoteAddr().String(); got != transport.LocalAddr().String() {
		t.Fatalf("validated peer = %s; want %s", got, transport.LocalAddr())
	}
	if err := client.UpdateKeys(true); err != nil {
		t.Fatalf("post-migration key update: %v", err)
	}
}
