//go:build unix

package netopen

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseMcastSpecBracketIPv6(t *testing.T) {
	g, iface, err := parseMcastSpec("[ff02::2]:eth0")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "ff02::2" || iface != "eth0" {
		t.Fatalf("group=%s iface=%q", g, iface)
	}
}

func TestParseMcastSpecIPv4(t *testing.T) {
	g, iface, err := parseMcastSpec("224.1.2.3:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "224.1.2.3" || iface != "127.0.0.1" {
		t.Fatalf("group=%s iface=%q", g, iface)
	}
}

func TestListenUDPJoinsIPv6GroupFromJoinGroupOption(t *testing.T) {
	iface := multicastIfaceName(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if err != nil {
		t.Fatalf("ipv6-join-group on UDP6-RECV: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestListenUDPJoinsIPv6GroupFromIPAddMembership(t *testing.T) {
	iface := multicastIfaceName(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ip-add-membership=[ff02::2]:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if err != nil {
		t.Fatalf("ip-add-membership on UDP6-RECV: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func multicastIfaceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 && ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 {
			return ifi.Name
		}
	}
	t.Skip("no multicast interface")
	return ""
}
