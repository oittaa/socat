package quicopen

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
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
