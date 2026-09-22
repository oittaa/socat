package netopen

import (
	"net"
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

func TestResolveRawIPTargetKeepsLiteralZone(t *testing.T) {
	addr, err := resolveRawIPTarget(t.Context(), addrconfig.Address{}, "ip6", addrconfig.HostFromText("fe80::1%eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if addr.Zone != "eth0" {
		t.Fatalf("zone=%q", addr.Zone)
	}
	if !addr.IP.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("ip=%v", addr.IP)
	}
}
