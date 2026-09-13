package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPNetworkWithListenDefaultPrecedence(t *testing.T) {
	opts := xio.Options{DefaultListenIPVersion: xio.IPv6}

	if got := udpNetworkWithListenDefault(opts, mustAddr(t, parse.Spec{})); got != "udp6" {
		t.Fatalf("process default: got %q want udp6", got)
	}
	opts.IPVersion = xio.IPv4
	if got := udpNetworkWithListenDefault(opts, mustAddr(t, parse.Spec{})); got != "udp4" {
		t.Fatalf("options: got %q want udp4", got)
	}
	s := parse.Spec{Options: []parse.Option{{Name: "pf", Value: "ip4", Has: true}}}
	opts.IPVersion = xio.IPv6
	if got := udpNetworkWithListenDefault(opts, mustAddr(t, s)); got != "udp4" {
		t.Fatalf("pf: got %q want udp4", got)
	}
}

func TestNetworkUDPIgnoresDefaultListenIP6(t *testing.T) {
	opts := xio.Options{DefaultListenIPVersion: xio.IPv6}
	if got := NetworkUDP(opts, mustAddr(t, parse.Spec{}), "udp4"); got != "udp4" {
		t.Fatalf("got %q want udp4", got)
	}
}
