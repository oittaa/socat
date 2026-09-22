package netopen

import (
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
	same := userPeer(ip, 9, "eth0")
	other := userPeer(ip, 9, "eth1")
	if udpForkAddrIsPeer(same, other) {
		t.Fatal("scoped peers on eth0 and eth1 matched")
	}
	if !udpForkAddrIsPeer(same, userPeer(ip, 9, "eth0")) {
		t.Fatal("identical scoped peers did not match")
	}
	if udpForkAddrIsPeer(same, userPeer(ip, 9, "")) {
		t.Fatal("scoped peer matched an unzoned address")
	}
}

func TestUDPForkAddrIsPeerMatchesZoneNameAndIndex(t *testing.T) {
	ifi := firstInterface(t)
	ip := net.ParseIP("fe80::1")
	byName := userPeer(ip, 9, ifi.Name)
	byIndex := userPeer(ip, 9, strconv.Itoa(ifi.Index))
	if !udpForkAddrIsPeer(byName, byIndex) {
		t.Fatalf("%s and index %d did not match", ifi.Name, ifi.Index)
	}
}

func TestKernelScopeIsNotZoneText(t *testing.T) {
	ifi := firstInterface(t)
	ip := net.ParseIP("fe80::1")
	scope := uint32(ifi.Index) + 1
	kernel := &udpPeer{UDPAddr: &net.UDPAddr{IP: ip, Port: 9, Zone: ifi.Name}, scope: scope}
	named := userPeer(ip, 9, ifi.Name)
	if udpForkAddrIsPeer(kernel, named) {
		t.Fatal("kernel scope was ignored in favor of zone text")
	}
	otherText := &udpPeer{UDPAddr: &net.UDPAddr{IP: ip, Port: 9, Zone: "eth9"}, scope: scope}
	if !udpForkAddrIsPeer(kernel, otherText) {
		t.Fatal("identical kernel scopes did not match")
	}
	_, id, err := udpPeerIPv6Addr(&net.UDPAddr{IP: ip, Port: 9, Zone: ifi.Name}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if id != scope {
		t.Fatalf("connect scope %d want kernel scope %d", id, scope)
	}
}

func TestUDPPeerIPv6AddrAcceptsNumericZone(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: "7"}
	_, zone, err := udpPeerIPv6Addr(peer, 0)
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
	_, zone, err := udpPeerIPv6Addr(peer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if zone != uint32(ifi.Index) {
		t.Fatalf("zone id %d want %d", zone, ifi.Index)
	}
}

func userPeer(ip net.IP, port int, zone string) *udpPeer {
	return &udpPeer{UDPAddr: &net.UDPAddr{IP: ip, Port: port, Zone: zone}}
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
