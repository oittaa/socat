package netopen

import (
	"net"
	"strconv"
	"testing"
)

func TestUDPAddrIsPeerComparesIPv6Zone(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	same := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}
	other := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth1"}
	if udpAddrIsPeer(same, other) {
		t.Fatal("scoped peers on eth0 and eth1 matched")
	}
	if !udpAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}) {
		t.Fatal("identical scoped peers did not match")
	}
	plain := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
	if !udpAddrIsPeer(plain, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}) {
		t.Fatal("unzoned IPv4 peers did not match")
	}
	if udpAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9}) {
		t.Fatal("scoped peer matched an unzoned address")
	}
}

func TestUDPAddrIsPeerMatchesZoneNameAndIndex(t *testing.T) {
	ifi := firstInterface(t)
	ip := net.ParseIP("fe80::1")
	byName := &net.UDPAddr{IP: ip, Port: 9, Zone: ifi.Name}
	byIndex := &net.UDPAddr{IP: ip, Port: 9, Zone: strconv.Itoa(ifi.Index)}
	if !udpAddrIsPeer(byName, byIndex) {
		t.Fatalf("%s and index %d did not match", ifi.Name, ifi.Index)
	}
}

func TestUDPPeerIPv6AddrAcceptsNumericZone(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: "7"}
	_, zone, err := udpPeerIPv6Addr(peer)
	if err != nil {
		t.Fatal(err)
	}
	if zone != 7 {
		t.Fatalf("zone id %d", zone)
	}
}

func firstInterface(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Index <= 0 || ifaces[i].Name == "" {
			continue
		}
		return &ifaces[i]
	}
	t.Skip("no up network interface")
	return nil
}
