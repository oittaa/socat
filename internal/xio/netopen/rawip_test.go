package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestNetworkIPFromHostMappedLiteral(t *testing.T) {
	s := addrconfig.Address{}
	s.Network.TargetSet = true
	s.Network.Target = addrconfig.HostFromText("[::ffff:127.0.0.1]")
	if got := NetworkIPFromHost(nil, s, "ip4"); got != "ip4" {
		t.Fatalf("mapped literal want ip4 got %s", got)
	}
	s.Network.Target = addrconfig.HostFromText("[::1]")
	if got := NetworkIPFromHost(nil, s, "ip4"); got != "ip6" {
		t.Fatalf("::1 want ip6 got %s", got)
	}
	s.Network.Target = addrconfig.HostFromText("127.0.0.1")
	if got := NetworkIPFromHost(nil, s, "ip6"); got != "ip4" {
		t.Fatalf("IPv4 literal want ip4 got %s", got)
	}
}
