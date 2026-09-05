package dtls13

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestNewHandshakeDoesNotBlackholeEstablishedPeerWithoutCID(t *testing.T) {
	a, b := handshakeConfigs(t)
	a.DisableMigration, b.DisableMigration = true, true
	l, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Client(ctx, testUDP(t), l.Addr(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := l.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := udpAddress(client.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	// Inject a second ClientHello with the established connection's source.
	_, err = newClientSession(a, func(packet []byte) error { l.receive(packet, peer); return nil }, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write([]byte("existing association")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := server.Read(buffer)
	if err != nil || string(buffer[:n]) != "existing association" {
		t.Fatalf("unauthenticated ClientHello displaced the established peer: %q, %v", buffer[:n], err)
	}
}

func TestConcurrentListenerSessionsRemainIsolated(t *testing.T) {
	a, b := handshakeConfigs(t)
	l, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const count = 8
	type clientResult struct {
		conn *Conn
		err  error
	}
	results := make(chan clientResult, count)
	for range count {
		transport := testUDP(t)
		go func() {
			conn, err := Client(ctx, transport, l.Addr(), a)
			results <- clientResult{conn, err}
		}()
	}
	var clients, servers []*Conn
	for i := range count {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		client := result.conn
		t.Cleanup(func() { _ = client.Close() })
		clients = append(clients, client)
		if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for range count {
		conn, err := l.AcceptContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		server := conn.(*Conn)
		servers = append(servers, server)
		if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 8)
		n, err := server.Read(buffer)
		if err != nil || n != 1 {
			t.Fatalf("association read: %d, %v", n, err)
		}
		if _, err := server.Write(buffer[:n]); err != nil {
			t.Fatal(err)
		}
	}
	for i, client := range clients {
		buffer := make([]byte, 8)
		n, err := client.Read(buffer)
		if err != nil || n != 1 || buffer[0] != byte(i) {
			t.Fatalf("association %d received another client's traffic: %x, %v", i, buffer[:n], err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, server := range servers {
		<-server.done
	}
	if l.packets.used.Load() != 0 || l.fragments.used.Load() != 0 {
		t.Fatal("closed listener retained buffered packet or fragment charges")
	}
}

func TestListenerBoundsPendingHandshakes(t *testing.T) {
	_, b := handshakeConfigs(t)
	l, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	m := handshakeMessage{typ: msgClientHello, body: make([]byte, 4096)}
	fragment := fragmentFor(t, m, 0, 1)
	packet, err := encodePlainRecord(contentHandshake, 0, fragment)
	if err != nil {
		t.Fatal(err)
	}
	for port := uint16(1); port <= 96; port++ {
		l.receive(packet, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port))
	}
	l.mu.Lock()
	var pending []*Conn
	for c := range l.connections {
		pending = append(pending, c)
	}
	l.mu.Unlock()
	if len(pending) != 0 {
		t.Fatalf("unverified fragments allocated %d associations", len(pending))
	}
	l.mu.Lock()
	entries, routes := len(l.hellos), len(l.cids)
	l.mu.Unlock()
	if entries == 0 || entries > maxHelloEntries || routes != 0 || l.helloBudget.used.Load() > l.helloBudget.limit {
		t.Fatal("unverified fragment cache exceeded its bounds or allocated CIDs")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range pending {
		<-c.done
	}
	if l.packets.used.Load() != 0 || l.fragments.used.Load() != 0 || l.helloBudget.used.Load() != 0 {
		t.Fatal("abandoned incomplete handshakes leaked their memory budget")
	}
}

func TestFragmentBudgetConcurrentReservationAndRelease(t *testing.T) {
	budget := &memoryBudget{limit: 4096}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 1000 {
				if budget.reserve(2048) {
					if budget.used.Load() > budget.limit {
						t.Error("concurrent reservations exceeded the listener budget")
					}
					budget.release(2048)
				}
			}
		})
	}
	wg.Wait()
	r := reassembler{budget: budget}
	first := handshakeFragment{typ: msgClientHello, total: 2048, body: []byte{1}}
	if accepted, err := r.insert(first, 0); !accepted || err != nil {
		t.Fatalf("initial fragment: %t, %v", accepted, err)
	}
	second := first
	second.sequence = 1
	if accepted, err := r.insert(second, 0); accepted || err != nil {
		t.Fatalf("over-budget fragment was not discarded without ACK: %t, %v", accepted, err)
	}
	r.clear()
	if budget.used.Load() != 0 {
		t.Fatal("fragment cleanup did not release the reservation")
	}
}
