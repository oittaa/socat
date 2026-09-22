package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestResolveIPTargetKeepsIPv6Zone(t *testing.T) {
	ctx := t.Context()
	cases := []addrconfig.HostTarget{
		addrconfig.HostFromText("[fe80::1%eth0]"),
		addrconfig.HostFromText("fe80::1%eth0"),
		{Name: "fe80::1%eth0"},
	}
	for _, host := range cases {
		ip, zone, err := ResolveIPTarget(ctx, addrconfig.Address{}, "tcp6", host)
		if err != nil {
			t.Fatal(err)
		}
		if zone != "eth0" {
			t.Fatalf("%s zone=%q", host.Original(), zone)
		}
		if !ip.Equal(net.ParseIP("fe80::1")) {
			t.Fatalf("%s ip=%v", host.Original(), ip)
		}
	}
}

func TestLookupIPKeepsIPv6Zone(t *testing.T) {
	addrs, err := LookupIP(t.Context(), addrconfig.Address{}, "ip6", "[fe80::1%eth0]")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].Zone != "eth0" || !addrs[0].IP.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("LookupIP=%v", addrs)
	}
}

func TestTCPListenAddressKeepsIPv6Zone(t *testing.T) {
	config := decodeListen(t, "TCP6-LISTEN:0,bind=[fe80::1%eth0]")
	addr, err := TCPListenAddress(t.Context(), config, "tcp6", config.Network.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "fe80::1%eth0" {
		t.Fatalf("listen address %q", addr)
	}
}
