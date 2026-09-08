package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPNetworkWithListenDefaultPrecedence(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")

	if got := udpNetworkWithListenDefault(&xio.Global{}, parse.Spec{}); got != "udp6" {
		t.Fatalf("environment: got %q want udp6", got)
	}
	if got := udpNetworkWithListenDefault(&xio.Global{IPVersion: xio.IPv4}, parse.Spec{}); got != "udp4" {
		t.Fatalf("global: got %q want udp4", got)
	}
	s := parse.Spec{Options: []parse.Option{{Name: "pf", Value: "ip4", Has: true}}}
	if got := udpNetworkWithListenDefault(&xio.Global{IPVersion: xio.IPv6}, s); got != "udp4" {
		t.Fatalf("pf: got %q want udp4", got)
	}
}

func TestNetworkUDPIgnoresDefaultListenIP6(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	if got := NetworkUDP(&xio.Global{}, parse.Spec{}, "udp4"); got != "udp4" {
		t.Fatalf("got %q want udp4", got)
	}
}
