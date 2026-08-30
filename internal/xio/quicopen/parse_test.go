package quicopen

import (
	"crypto/tls"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestQUICTargetConnect(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:example.com:4433")
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := quicTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != "4433" {
		t.Fatalf("host=%q port=%q", host, port)
	}
}

func TestQUICTargetListen(t *testing.T) {
	s, err := parse.ParseSpec("QUIC-LISTEN:4433")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := quicTarget(s, true)
	if err != nil {
		t.Fatal(err)
	}
	if port != "4433" {
		t.Fatalf("port=%q", port)
	}
}

func TestQUICTargetListenRequiresPort(t *testing.T) {
	s, err := parse.ParseSpec("QUIC-LISTEN")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := quicTarget(s, true); err == nil {
		t.Fatal("expected error")
	}
}

func TestQUICTargetConnectRequiresHostPort(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:onlyhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := quicTarget(s, false); err == nil {
		t.Fatal("expected error")
	}
}

func TestALPNDefault(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1")
	if err != nil {
		t.Fatal(err)
	}
	if alpnProto(s) != defaultALPN {
		t.Fatalf("alpn=%q", alpnProto(s))
	}
}

func TestALPNOption(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1,alpn=foo")
	if err != nil {
		t.Fatal(err)
	}
	if alpnProto(s) != "foo" {
		t.Fatalf("alpn=%q", alpnProto(s))
	}
}

func TestQUICConfigRequiresTLS13Maximum(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		_, err := quicConfig(s, &tls.Config{MaxVersion: version})
		if err == nil || !strings.Contains(err.Error(), "openssl-max-proto-version") || !strings.Contains(err.Error(), "TLS 1.3") {
			t.Fatalf("MaxVersion=%#x error=%v, want clear TLS 1.3 option error", version, err)
		}
	}
}

func TestQUICConfigEnforcesTLS13Minimum(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1,alpn=test")
	if err != nil {
		t.Fatal(err)
	}
	for _, maxVersion := range []uint16{0, tls.VersionTLS13} {
		original := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}
		setup, err := quicConfig(s, original)
		if err != nil {
			t.Fatal(err)
		}
		if setup.tls.MinVersion != tls.VersionTLS13 || setup.tls.MaxVersion != maxVersion {
			t.Fatalf("protocol bounds=%#x..%#x", setup.tls.MinVersion, setup.tls.MaxVersion)
		}
		if len(setup.tls.NextProtos) != 1 || setup.tls.NextProtos[0] != "test" {
			t.Fatalf("NextProtos=%q", setup.tls.NextProtos)
		}
		if original.MinVersion != tls.VersionTLS12 || len(original.NextProtos) != 0 {
			t.Fatal("quicConfig modified the caller's TLS config")
		}
	}
}

func TestQUICConfigHandshakeIdleTimeoutFromHandshakeTimeout(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1,handshake-timeout=0.2")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := quicConfig(s, &tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if setup.cfg.HandshakeIdleTimeout != 200*time.Millisecond {
		t.Fatalf("HandshakeIdleTimeout=%s want 200ms", setup.cfg.HandshakeIdleTimeout)
	}
}

func TestQUICConfigHandshakeIdleTimeoutIgnoresConnectTimeout(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1,connect-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := quicConfig(s, &tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if setup.cfg.HandshakeIdleTimeout != 30*time.Second {
		t.Fatalf("HandshakeIdleTimeout=%s want 30s default, not connect-timeout", setup.cfg.HandshakeIdleTimeout)
	}
}

func TestQUICConfigHandshakeIdleTimeoutOmittedUsesDefault(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := quicConfig(s, &tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if setup.cfg.HandshakeIdleTimeout != 30*time.Second {
		t.Fatalf("HandshakeIdleTimeout=%s want 30s default", setup.cfg.HandshakeIdleTimeout)
	}
}

func TestQUICConfigHandshakeIdleTimeoutZeroDisablesBound(t *testing.T) {
	s, err := parse.ParseSpec("QUIC:h:1,handshake-timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	if got := xio.HandshakeTimeout(s); got != 0 {
		t.Fatalf("HandshakeTimeout=%s want 0 (TLS/WS still treat 0 as no deadline)", got)
	}
	setup, err := quicConfig(s, &tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// quic-go populateConfig substitutes 5s when HandshakeIdleTimeout is 0.
	// The public option still means "unbounded"; we map that to a long
	// explicit duration rather than leaving the field at 0.
	if setup.cfg.HandshakeIdleTimeout != quicHandshakeIdleTimeoutDisabled {
		t.Fatalf("HandshakeIdleTimeout=%s want normalized %s", setup.cfg.HandshakeIdleTimeout, quicHandshakeIdleTimeoutDisabled)
	}
	if setup.cfg.HandshakeIdleTimeout == 0 || setup.cfg.HandshakeIdleTimeout == 5*time.Second || setup.cfg.HandshakeIdleTimeout == 30*time.Second {
		t.Fatalf("HandshakeIdleTimeout=%s is not an unbounded substitute", setup.cfg.HandshakeIdleTimeout)
	}
}

func TestQUICHandshakeIdleTimeoutDisabledDoesNotOverflowWhenDoubled(t *testing.T) {
	if quicHandshakeIdleTimeoutDisabled <= 0 {
		t.Fatal("disabled HandshakeIdleTimeout must be nonzero so quic-go does not substitute 5s")
	}
	if quicHandshakeIdleTimeoutDisabled > time.Duration(math.MaxInt64/2) {
		t.Fatalf("2*%s would overflow int64; quic-go handshakeTimeout doubles HandshakeIdleTimeout", quicHandshakeIdleTimeoutDisabled)
	}
}

func TestQUICDialAttemptTimeout(t *testing.T) {
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
			if got := quicDialAttemptTimeout(s); got != tc.want {
				t.Fatalf("quicDialAttemptTimeout(%q)=%s want %s", tc.spec, got, tc.want)
			}
		})
	}
}
