package proxyopen

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func holdAcceptedConn(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 1)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
}

func silentUDPPeer(t *testing.T) (port int, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { _ = pc.Close() }
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
	_, err = openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected timeout against stalled peer")
	}
	elapsed := time.Since(started)
	if elapsed < min || elapsed > max {
		t.Fatalf("elapsed %s want between %s and %s: %v", elapsed, min, max, err)
	}
}

func assertPROXYConnectStillRunning(t *testing.T, spec string, wait time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
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
	holdAcceptedConn(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	assertPROXYConnectStillRunning(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%d,handshake-timeout=0", port),
		1200*time.Millisecond)
}

func TestH3CONNECTHandshakeTimeoutStalledPeer(t *testing.T) {
	port, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectFailsNear(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,handshake-timeout=0.2", port),
		150*time.Millisecond, 1200*time.Millisecond)
}

func TestH3CONNECTHandshakeTimeoutZeroDoesNotApplyShortBound(t *testing.T) {
	port, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectStillRunning(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,handshake-timeout=0", port),
		1200*time.Millisecond)
}

func TestH3CONNECTConnectTimeoutBoundsSilentPeerWhenHandshakeTimeoutDisabled(t *testing.T) {
	port, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertPROXYConnectFailsNear(t,
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,connect-timeout=0.2,handshake-timeout=0", port),
		150*time.Millisecond, 1500*time.Millisecond)
}

func TestProxyHandshakeContextStopPreventsLateCancel(t *testing.T) {
	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	const iterations = 50
	for i := 0; i < iterations; i++ {
		var stop, fire func()
		setHandshakeTimerHook(func(s, f func()) func() {
			stop, fire = s, f
			return nil
		})
		parent, parentCancel := context.WithCancel(context.Background())
		ctx, stopTimer, cancel := proxyHandshakeContext(parent, time.Hour)
		if stop == nil || fire == nil || stopTimer == nil {
			parentCancel()
			cancel()
			t.Fatalf("iter %d: handshake timer hook did not arm", i)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			stop()
		}()
		go func() {
			defer wg.Done()
			<-start
			fire()
		}()
		close(start)
		wg.Wait()

		cancelled := ctx.Err()
		fire()
		fire()
		if cancelled == nil && ctx.Err() != nil {
			parentCancel()
			cancel()
			t.Fatalf("iter %d: late timer fire cancelled context after stop", i)
		}

		parentCancel()
		if ctx.Err() == nil {
			cancel()
			t.Fatalf("iter %d: parent cancel must still abort after handshake stop", i)
		}
		cancel()
	}
}

func TestProxyHandshakeContextStopThenFireDoesNotCancel(t *testing.T) {
	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	var stop, fire func()
	setHandshakeTimerHook(func(s, f func()) func() {
		stop, fire = s, f
		return nil
	})
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	ctx, _, cancel := proxyHandshakeContext(parent, time.Hour)
	defer cancel()
	stop()
	fire()
	fire()
	if ctx.Err() != nil {
		t.Fatalf("stop then fire cancelled handshake ctx: %v", ctx.Err())
	}
	parentCancel()
	if ctx.Err() == nil {
		t.Fatal("parent cancel must still abort after handshake stop")
	}
}

func TestProxyHandshakeContextFireThenStopTimesOut(t *testing.T) {
	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	var stop, fire func()
	setHandshakeTimerHook(func(s, f func()) func() {
		stop, fire = s, f
		return nil
	})
	ctx, _, cancel := proxyHandshakeContext(context.Background(), time.Hour)
	defer cancel()
	fire()
	stop()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("fire then stop want context.Canceled, got %v", ctx.Err())
	}
}

func TestH2CONNECTHandshakeTimerRaceKeepsBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	setHandshakeTimerHook(func(stop, fire func()) func() {
		return func() {
			stop()
			fire()
			fire()
		}
	})
	spec := fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0,handshake-timeout=5", port)
	for i := 0; i < 50; i++ {
		echoViaPROXY(t, spec)
	}
}

func TestH3CONNECTHandshakeTimerRaceKeepsBody(t *testing.T) {
	certs := writeTrustCerts(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certs.serverTLS},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(pc) }()
	defer func() { _ = srv.Close() }()

	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	setHandshakeTimerHook(func(stop, fire func()) func() {
		return func() {
			stop()
			fire()
			fire()
		}
	})
	spec := fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%d,verify=0,handshake-timeout=5", port)
	for i := 0; i < 50; i++ {
		echoViaPROXY(t, spec)
	}
}

func TestH2CONNECTTimeoutWonAfterConnectDoesNotReturnTunnel(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setHandshakeTimerHook(nil) })
	setHandshakeTimerHook(func(stop, fire func()) func() {
		return func() {
			fire()
			stop()
		}
	})
	s, err := parse.ParseSpec(fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0,handshake-timeout=5", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		_ = o.Close()
		t.Fatal("timeout-won CONNECT must not return a live tunnel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("timeout-won want context.Canceled, got %v", err)
	}
}
