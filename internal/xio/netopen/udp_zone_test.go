package netopen

import (
	"errors"
	"net"
	"strconv"
	"testing"
)

func TestUDPAddrIsPeerIgnoresZone(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	same := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}
	other := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth1"}
	if !udpAddrIsPeer(same, other) {
		t.Fatal("same address and port with different zones did not match")
	}
	if !udpAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}) {
		t.Fatal("identical scoped peers did not match")
	}
	plain := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
	if !udpAddrIsPeer(plain, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}) {
		t.Fatal("unzoned IPv4 peers did not match")
	}
	if !udpAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9}) {
		t.Fatal("scoped peer did not match an unzoned address")
	}
	if udpAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 10, Zone: "eth0"}) {
		t.Fatal("different ports matched")
	}
}

func TestUDPForkAddrIsPeerComparesIPv6Zone(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	same := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}
	other := &net.UDPAddr{IP: ip, Port: 9, Zone: "eth1"}
	if udpForkAddrIsPeer(same, other) {
		t.Fatal("scoped peers on eth0 and eth1 matched")
	}
	if !udpForkAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9, Zone: "eth0"}) {
		t.Fatal("identical scoped peers did not match")
	}
	if udpForkAddrIsPeer(same, &net.UDPAddr{IP: ip, Port: 9}) {
		t.Fatal("scoped peer matched an unzoned address")
	}
}

func TestUDPForkAddrIsPeerMatchesZoneNameAndIndex(t *testing.T) {
	ifi := firstInterface(t)
	ip := net.ParseIP("fe80::1")
	byName := &net.UDPAddr{IP: ip, Port: 9, Zone: ifi.Name}
	byIndex := &net.UDPAddr{IP: ip, Port: 9, Zone: strconv.Itoa(ifi.Index)}
	if !udpForkAddrIsPeer(byName, byIndex) {
		t.Fatalf("%s and index %d did not match", ifi.Name, ifi.Index)
	}
}

func TestZoneLookupTriesInterfaceNameBeforeNumeric(t *testing.T) {
	prev := lookupInterface
	t.Cleanup(func() { lookupInterface = prev })
	lookupInterface = func(name string) (*net.Interface, error) {
		if name == "2" {
			return &net.Interface{Index: 5, Name: "2"}, nil
		}
		return nil, errors.New("no such interface")
	}
	if got, ok := udpZoneIndex("2"); !ok || got != 5 {
		t.Fatalf("udpZoneIndex=%d ok=%v want name index 5", got, ok)
	}
	id, err := ipv6ScopeID("2")
	if err != nil || id != 5 {
		t.Fatalf("ipv6ScopeID=%d err=%v want name index 5", id, err)
	}
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: "2"}
	_, zone, err := udpPeerIPv6Addr(peer)
	if err != nil {
		t.Fatal(err)
	}
	if zone != 5 {
		t.Fatalf("connect zone id %d want name index 5", zone)
	}

	lookupInterface = func(string) (*net.Interface, error) {
		return nil, errors.New("no such interface")
	}
	if got, ok := udpZoneIndex("7"); !ok || got != 7 {
		t.Fatalf("numeric udpZoneIndex=%d ok=%v", got, ok)
	}
	_, zone, err = udpPeerIPv6Addr(&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: "7"})
	if err != nil {
		t.Fatal(err)
	}
	if zone != 7 {
		t.Fatalf("numeric connect zone id %d", zone)
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

func TestUDPPeerIPv6AddrResolvesInterfaceName(t *testing.T) {
	ifi := firstInterface(t)
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: ifi.Name}
	_, zone, err := udpPeerIPv6Addr(peer)
	if err != nil {
		t.Fatal(err)
	}
	if zone != uint32(ifi.Index) {
		t.Fatalf("zone id %d want %d", zone, ifi.Index)
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
