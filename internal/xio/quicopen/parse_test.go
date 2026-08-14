package quicopen

import (
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

func TestUDPNetwork(t *testing.T) {
	if udpNetwork("tcp4") != "udp4" || udpNetwork("tcp6") != "udp6" || udpNetwork("tcp") != "udp" {
		t.Fatal(udpNetwork("tcp4"), udpNetwork("tcp6"), udpNetwork("tcp"))
	}
}
