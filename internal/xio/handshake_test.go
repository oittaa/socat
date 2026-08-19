package xio

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

func TestWithHandshakeDeadlineBoundsBlockedPeer(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	started := time.Now()
	err := WithHandshakeDeadline(client, 30*time.Millisecond, func() error {
		var b [1]byte
		_, err := client.Read(b[:])
		return err
	})
	if err == nil {
		t.Fatal("blocked handshake did not time out")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s", elapsed)
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
