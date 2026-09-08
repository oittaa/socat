package dtls13

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func testUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func connectionPair(t *testing.T) (*Conn, *Conn, *Listener) {
	t.Helper()
	a, b := handshakeConfigs(t)
	listener, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Client(ctx, testUDP(t), listener.Addr(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	t.Cleanup(func() { _ = server.Close() })
	for _, c := range []*Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server, listener
}

func TestListenerCloseUnblocksConnectionsAndAccept(t *testing.T) {
	_, server, listener := connectionPair(t)
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 2)
	wg.Go(func() { _, err := server.Read(make([]byte, 1)); errorsSeen <- err })
	wg.Go(func() { _, err := listener.Accept(); errorsSeen <- err })
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener closure did not unblock its operation: %v", err)
		}
	}
}
