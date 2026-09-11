package netopen

import (
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestDialUDP6IPv4LiteralKeepsFamily(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := parse.Spec{Type: "UDP6", Options: []parse.Option{{Name: "ai-v4mapped"}}}
	_, err = dialUDPForSpec(dialRequest{
		ctx:     t.Context(),
		network: "udp6",
		timeout: time.Second,
		config:  mustAddr(t, s),
	}, nil, ln.LocalAddr().(*net.UDPAddr))
	if err == nil {
		t.Fatal("UDP6 to an IPv4 literal succeeded; want family mismatch")
	}
}

func TestRawIP6MappedHostnameSwitchesToIPv4(t *testing.T) {
	mapped := net.ParseIP("::ffff:192.0.2.1")
	network := xio.DialNetwork("ip6", mapped)
	if network != "ip4" {
		t.Fatalf("DialNetwork=%s want ip4", network)
	}
	raddr := &net.IPAddr{IP: mapped.To4()}
	if err := requireRawIPFamily("IP6-SENDTO", network, raddr, "raw-v4mapped.test"); err != nil {
		t.Fatal(err)
	}
	if err := requireRawIPFamily("IP6-SENDTO", "ip6", &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}, "192.0.2.1"); err == nil {
		t.Fatal("IP6-SENDTO IPv4 literal: want family mismatch")
	}
}
