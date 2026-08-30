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

func TestCombinedConnectHandshakeTimeout(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want time.Duration
	}{
		{name: "connect-shorter-than-handshake", spec: "QUIC:h:1,connect-timeout=0.2,handshake-timeout=5", want: 200 * time.Millisecond},
		{name: "handshake-zero-connect-still-caps", spec: "QUIC:h:1,connect-timeout=0.2,handshake-timeout=0", want: 200 * time.Millisecond},
		{name: "handshake-zero-no-connect", spec: "QUIC:h:1,handshake-timeout=0", want: 0},
		{name: "omitted-handshake-default", spec: "QUIC:h:1", want: 30 * time.Second},
		{name: "omitted-handshake-connect-caps", spec: "QUIC:h:1,connect-timeout=0.2", want: 200 * time.Millisecond},
		{name: "handshake-shorter-than-connect", spec: "QUIC:h:1,connect-timeout=5,handshake-timeout=0.2", want: 200 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := CombinedConnectHandshakeTimeout(s); got != tc.want {
				t.Fatalf("CombinedConnectHandshakeTimeout(%q)=%s want %s", tc.spec, got, tc.want)
			}
		})
	}
}

func TestQUICHandshakeIdleTimeoutMapping(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want time.Duration
	}{
		{name: "explicit", spec: "QUIC:h:1,handshake-timeout=0.2", want: 200 * time.Millisecond},
		{name: "omitted-default", spec: "QUIC:h:1", want: defaultHandshakeTimeout},
		{name: "zero-disables", spec: "QUIC:h:1,handshake-timeout=0", want: QUICHandshakeIdleTimeoutDisabled},
		{name: "ignores-connect-timeout", spec: "QUIC:h:1,connect-timeout=0.05", want: defaultHandshakeTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := QUICHandshakeIdleTimeout(s); got != tc.want {
				t.Fatalf("QUICHandshakeIdleTimeout(%q)=%s want %s", tc.spec, got, tc.want)
			}
		})
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

func TestWithHandshakeDeadlineClearsAfterSuccess(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if err := WithHandshakeDeadline(client, time.Hour, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := client.Read(b[:])
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("handshake deadline was left on the connection: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := server.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read after cleared deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not complete after peer wrote")
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
