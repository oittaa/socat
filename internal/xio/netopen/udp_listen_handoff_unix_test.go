//go:build linux

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
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if attempts != 2 {
		t.Fatalf("dial attempts = %d, want 2 within one Accept", attempts)
	}
	got, err := io.ReadAll(io.LimitReader(conn, int64(len("opener"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "opener" {
		t.Fatalf("opener after retry = %q, want opener", got)
	}
}

func TestUDPListenForkSlowDialKeepsPeekedOpener(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.03")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	listener := o.Listener.(*udpForkListener)
	listener.dialSession = func(ctx context.Context, network string, local, remote *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
		time.Sleep(60 * time.Millisecond)
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
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	assertUDPRead(t, conn, "opener", nil)
}

func TestUDPListenForkPersistentDialFailureDropsOpenerAndServesNextPeer(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	listener := o.Listener.(*udpForkListener)

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
	firstPort := firstClient.LocalAddr().(*net.UDPAddr).Port
	failedTwice := make(chan struct{})
	firstFailures := 0
	wantDialErr := errors.New("persistent child dial failure")
	listener.dialSession = func(ctx context.Context, network string, local, remote *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
		if remote.Port == firstPort {
			firstFailures++
			if firstFailures == udpForkDialMaxAttempts {
				close(failedTwice)
			}
			return nil, wantDialErr
		}
		return dialUDPSession(ctx, network, local, remote, s)
	}

	accepted := startUDPAccept(listener)
	if _, err := firstClient.Write([]byte("drop-me")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-failedTwice:
	case <-time.After(time.Second):
		t.Fatal("listener did not stop retrying the failed opener")
	}
	if _, err := secondClient.Write([]byte("kept")); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "second peer after failed opener")
	t.Cleanup(func() { _ = conn.Close() })
	if firstFailures != udpForkDialMaxAttempts {
		t.Fatalf("failed opener dial attempts = %d, want %d", firstFailures, udpForkDialMaxAttempts)
	}
	assertUDPRead(t, conn, "kept", nil)
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
