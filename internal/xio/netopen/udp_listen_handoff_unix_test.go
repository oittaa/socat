//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestUDPListenForkDialFailureKeepsOpener(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.25")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	listener, ok := o.Listener.(*udpForkListener)
	if !ok {
		t.Fatalf("listener type %T, want *udpForkListener", o.Listener)
	}

	wantDialErr := errors.New("forced child dial failure")
	attempts := 0
	listener.dialSession = func(ctx context.Context, network string, local, remote *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
		attempts++
		if attempts == 1 {
			return nil, wantDialErr
		}
		return dialUDPSession(ctx, network, local, remote, s)
	}

	client, err := net.DialUDP("udp4", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("opener")); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, wantDialErr) {
		t.Fatalf("first Accept error = %v, want %v", err, wantDialErr)
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	got, err := io.ReadAll(io.LimitReader(conn, int64(len("opener"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "opener" {
		t.Fatalf("opener after retry = %q, want opener", got)
	}
}

func TestUDPListenForkRoutesQueuedPeerPacketsToSession(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.25")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	listener := o.Listener.(*udpForkListener)

	dialEntered := make(chan struct{})
	releaseDial := make(chan struct{})
	dialReleased := false
	defer func() {
		if !dialReleased {
			close(releaseDial)
		}
	}()
	firstDial := true
	listener.dialSession = func(ctx context.Context, network string, local, remote *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
		if firstDial {
			firstDial = false
			close(dialEntered)
			<-releaseDial
		}
		return dialUDPSession(ctx, network, local, remote, s)
	}

	firstClient, err := net.DialUDP("udp4", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstClient.Close() })
	secondClient, err := net.DialUDP("udp4", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondClient.Close() })

	firstAccepted := startUDPAccept(listener)
	if _, err := firstClient.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialEntered:
	case <-time.After(time.Second):
		t.Fatal("first child dial did not start")
	}
	if _, err := secondClient.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := secondClient.Write(nil); err != nil {
		t.Fatal(err)
	}
	close(releaseDial)
	dialReleased = true

	first := waitUDPAccept(t, firstAccepted, 2*time.Second, "first peer")
	t.Cleanup(func() { _ = first.Close() })
	assertUDPRead(t, first, "first", nil)

	secondAccepted := startUDPAccept(listener)
	second := waitUDPAccept(t, secondAccepted, 2*time.Second, "queued second peer")
	t.Cleanup(func() { _ = second.Close() })
	assertUDPRead(t, second, "second", nil)
	assertUDPRead(t, second, "", io.EOF)
}

func assertUDPRead(t *testing.T, conn net.Conn, want string, wantErr error) {
	t.Helper()
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if !errors.Is(err, wantErr) || string(buf[:n]) != want {
		t.Fatalf("Read = %q, %v; want %q, %v", buf[:n], err, want, wantErr)
	}
}
