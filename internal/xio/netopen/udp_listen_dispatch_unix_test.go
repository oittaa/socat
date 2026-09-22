//go:build linux || darwin

package netopen

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUDPAddrFromSockaddrKeepsNumericZone(t *testing.T) {
	const index = 1<<30 - 1
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[15] = 1
	sa := &unix.SockaddrInet6{Port: 9, Addr: addr, ZoneId: index}

	got, err := udpPeerFromSockaddr(sa)
	if err != nil {
		t.Fatalf("missing interface index aborted the listener path: %v", err)
	}
	if got.scope != index || got.Zone != "" {
		t.Fatalf("scope=%d zone=%q want kernel scope %d", got.scope, got.Zone, index)
	}
}

func TestUDPAddrFromSockaddrKeepsRealInterfaceIndex(t *testing.T) {
	ifi := firstInterface(t)
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[15] = 1
	sa := &unix.SockaddrInet6{Port: 9, Addr: addr, ZoneId: uint32(ifi.Index)}
	got, err := udpPeerFromSockaddr(sa)
	if err != nil {
		t.Fatal(err)
	}
	if got.scope != uint32(ifi.Index) || got.Zone != "" {
		t.Fatalf("scope=%d zone=%q want kernel scope %d", got.scope, got.Zone, ifi.Index)
	}
}

func TestUDPAddrFromSockaddrIgnoresUnscoped(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1).To4()
	var addr [4]byte
	copy(addr[:], ip)
	sa := &unix.SockaddrInet4{Port: 9, Addr: addr}
	got, err := udpPeerFromSockaddr(sa)
	if err != nil {
		t.Fatal(err)
	}
	if got.scope != 0 || got.Zone != "" || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("addr=%v scope=%d", got, got.scope)
	}
}
