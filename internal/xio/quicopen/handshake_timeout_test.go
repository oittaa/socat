package quicopen

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

func silentUDPPeer(t *testing.T) (port int, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { _ = pc.Close() }
}

func assertQUICConnectFailsNear(t *testing.T, spec string, min, max time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openQUICConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected timeout against silent UDP peer")
	}
	elapsed := time.Since(started)
	if elapsed < min || elapsed > max {
		t.Fatalf("elapsed %s want between %s and %s: %v", elapsed, min, max, err)
	}
}

func TestQUICConnectTimeoutBoundsSilentPeerBeforeHandshakeTimeout(t *testing.T) {
	port, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertQUICConnectFailsNear(t,
		fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,connect-timeout=0.2,handshake-timeout=5", port),
		150*time.Millisecond, 1500*time.Millisecond)
}

func TestQUICConnectTimeoutBoundsSilentPeerWhenHandshakeTimeoutDisabled(t *testing.T) {
	port, cleanup := silentUDPPeer(t)
	defer cleanup()
	assertQUICConnectFailsNear(t,
		fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,connect-timeout=0.2,handshake-timeout=0", port),
		150*time.Millisecond, 1500*time.Millisecond)
}
