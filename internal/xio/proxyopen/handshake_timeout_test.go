package proxyopen

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func holdAcceptedConn(t *testing.T, ln net.Listener) <-chan struct{} {
	t.Helper()
	started := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil {
			return
		}
		close(started)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	return started
}

func silentUDPPeer(t *testing.T) (port int, started <-chan struct{}, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		if _, _, err := pc.ReadFrom(buf); err != nil {
			return
		}
		close(got)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, got, func() { _ = pc.Close() }
}

func assertPROXYConnectFailsNear(t *testing.T, spec string, min, max time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected timeout against stalled peer")
	}
	elapsed := time.Since(started)
	if elapsed < min || elapsed > max {
		t.Fatalf("elapsed %s want between %s and %s: %v", elapsed, min, max, err)
	}
}

func assertPROXYConnectStillRunning(t *testing.T, spec string, started <-chan struct{}, wait time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("handshake-timeout=0 returned before the peer saw traffic: %v", err)
	case <-ctx.Done():
		t.Fatal("handshake-timeout=0 ended before the peer saw traffic")
	}
	// Margin past the 0.2s handshake bound. The peer's first byte is the barrier.
	select {
	case err := <-done:
		t.Fatalf("handshake-timeout=0 returned after %v (must not apply a 0.2s bound)", err)
	case <-time.After(wait):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("open did not return after cancel")
	}
}

func TestH2cCONNECTHandshakeTimeoutStalledPeer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	holdAcceptedConn(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	assertPROXYConnectFailsNear(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%d,handshake-timeout=0.2", port),
		150*time.Millisecond, 1200*time.Millisecond)
}

func TestH2cCONNECTHandshakeTimeoutZeroDoesNotApplyShortBound(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	started := holdAcceptedConn(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	assertPROXYConnectStillRunning(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%d,handshake-timeout=0", port),
		started, 1200*time.Millisecond)
}

func TestH3CONNECTHandshakeTimeoutStalledPeer(t *testing.T) {
	port, _, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectFailsNear(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,handshake-timeout=0.2", port),
		150*time.Millisecond, 1200*time.Millisecond)
}

func TestH3CONNECTHandshakeTimeoutZeroDoesNotApplyShortBound(t *testing.T) {
	port, started, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectStillRunning(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,handshake-timeout=0", port),
		started, 1200*time.Millisecond)
}

func TestH3CONNECTConnectTimeoutBoundsSilentPeerWhenHandshakeTimeoutDisabled(t *testing.T) {
	port, _, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectFailsNear(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,connect-timeout=0.2,handshake-timeout=0", port),
		150*time.Millisecond, 1500*time.Millisecond)
}
