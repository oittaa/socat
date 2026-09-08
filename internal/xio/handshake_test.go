package xio

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestConnectTimeoutIndependentOfHandshakeTimeout(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:1,connect-timeout=0.25")
	if err != nil {
		t.Fatal(err)
	}
	if got := ConnectTimeout(s); got != 250*time.Millisecond {
		t.Fatalf("ConnectTimeout=%s", got)
	}
	if got := HandshakeTimeout(s); got != defaultHandshakeTimeout {
		t.Fatalf("HandshakeTimeout=%s want default %s", got, defaultHandshakeTimeout)
	}
}

func TestQUICHandshakeIdleTimeoutDisabledDoesNotOverflowWhenDoubled(t *testing.T) {
	if QUICHandshakeIdleTimeoutDisabled <= 0 {
		t.Fatal("disabled HandshakeIdleTimeout must be nonzero so quic-go does not substitute 5s")
	}
	if QUICHandshakeIdleTimeoutDisabled > time.Duration(math.MaxInt64/2) {
		t.Fatalf("2*%s would overflow int64; quic-go handshakeTimeout doubles HandshakeIdleTimeout", QUICHandshakeIdleTimeoutDisabled)
	}
}

func TestSingleUseDialerRejectsSecondUse(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	reused := errors.New("already used")
	d := SingleUseDialer(c1, reused)
	got, err := d(context.Background(), "tcp", "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if got != c1 {
		t.Fatal("first dial did not return the connection")
	}
	if _, err := d(context.Background(), "tcp", "ignored"); !errors.Is(err, reused) {
		t.Fatalf("second dial error=%v want %v", err, reused)
	}
}

func TestRememberTLSPeerBoundsIncompleteHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- no server exists; this tests timeout behavior

	err := RememberTLSPeer(&Global{}, tlsClient, 30*time.Millisecond)
	if err == nil {
		t.Fatal("incomplete TLS handshake did not time out")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error=%v", err)
	}
}
