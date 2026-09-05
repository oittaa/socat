package dtls13

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
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

func TestConnDatagramsKeyUpdateAndCIDRotation(t *testing.T) {
	client, server, _ := connectionPair(t)
	for _, c := range []*Conn{client, server} {
		state := c.ConnectionState()
		if !state.HandshakeComplete || state.Version != version13 || len(state.VerifiedChains) == 0 {
			t.Fatal("connection exposed an unverified handshake")
		}
		if err := c.UpdateKeys(true); err != nil {
			t.Fatal(err)
		}
		if err := c.RotateConnectionID(); err != nil {
			t.Fatal(err)
		}
	}
	for _, message := range []string{"first datagram", "second datagram"} {
		if n, err := client.Write([]byte(message)); err != nil || n != len(message) {
			t.Fatalf("write: %d, %v", n, err)
		}
	}
	buffer := make([]byte, 6)
	if n, err := server.Read(buffer); err != nil || string(buffer[:n]) != "first " {
		t.Fatalf("short datagram read: %q, %v", buffer[:n], err)
	}
	buffer = make([]byte, 64)
	if n, err := server.Read(buffer); err != nil || string(buffer[:n]) != "second datagram" {
		t.Fatalf("datagram boundaries: %q, %v", buffer[:n], err)
	}
	if _, err := client.Write(make([]byte, client.MaxDatagramSize()+1)); !errors.Is(err, errRecordOverflow) {
		t.Fatalf("oversized datagram accepted: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("close_notify was not exposed as EOF: %v", err)
	}
	if _, err := server.Write([]byte("half close reply")); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(buffer); err != nil || string(buffer[:n]) != "half close reply" {
		t.Fatalf("read after CloseWrite: %q, %v", buffer[:n], err)
	}
}

func TestConnDeadlineChangesAndRecovery(t *testing.T) {
	client, server, _ := connectionPair(t)
	result := make(chan error, 1)
	go func() { _, err := server.Read(make([]byte, 64)); result <- err }()
	if err := server.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline did not unblock: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.SetWriteDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("must not send")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write deadline: %v", err)
	}
	// An expired application write deadline must not prevent protocol ACKs.
	if err := server.UpdateKeys(true); err != nil {
		t.Fatal(err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	marker := []byte("after deadline reset")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := server.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("deadline recovery/unsent datagram: %q, %v", buffer[:n], err)
	}
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

func TestClientHandshakeCancellationClosesOwnedTransport(t *testing.T) {
	a, _ := handshakeConfigs(t)
	peer := testUDP(t)
	transport := testUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := Client(ctx, transport, peer.LocalAddr(), a); result <- err }()
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("handshake cancellation: %v", err)
	}
	if _, err := transport.WriteToUDP([]byte("closed"), peer.LocalAddr().(*net.UDPAddr)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cancelled client retained its transport: %v", err)
	}
}
