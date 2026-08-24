package quicopen

import (
	"crypto/tls"
	"strings"
	"testing"

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

func TestUDPNetwork(t *testing.T) {
	if udpNetwork("tcp4") != "udp4" || udpNetwork("tcp6") != "udp6" || udpNetwork("tcp") != "udp" {
		t.Fatal(udpNetwork("tcp4"), udpNetwork("tcp6"), udpNetwork("tcp"))
	}
}
