package xio

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
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

func TestWithHandshakeDeadlineZeroDoesNotBound(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan error, 1)
	go func() {
		done <- WithHandshakeDeadline(client, 0, func() error {
			var b [1]byte
			_, err := client.Read(b[:])
			return err
		})
	}()
	select {
	case err := <-done:
		t.Fatalf("unbounded handshake returned before the peer wrote: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	if _, err := server.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unbounded handshake: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unbounded handshake did not complete after the peer wrote")
	}
}

func TestHandshakeTimeoutValues(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want time.Duration
	}{
		{name: "explicit", spec: "TLS:127.0.0.1:1,handshake-timeout=0.2", want: 200 * time.Millisecond},
		{name: "zero-disables", spec: "TLS:127.0.0.1:1,handshake-timeout=0", want: 0},
		{name: "omitted-default", spec: "TLS:127.0.0.1:1", want: defaultHandshakeTimeout},
		{name: "connect-timeout-not-reused", spec: "TLS:127.0.0.1:1,connect-timeout=0.05", want: defaultHandshakeTimeout},
		{name: "handshake-wins", spec: "TLS:127.0.0.1:1,connect-timeout=5,handshake-timeout=0.2", want: 200 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := HandshakeTimeout(s); got != tc.want {
				t.Fatalf("HandshakeTimeout(%q)=%s want %s", tc.spec, got, tc.want)
			}
		})
	}
}

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
