//go:build linux || darwin

package netopen

import (
	"net"
	"strconv"
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

	got, err := udpAddrFromSockaddr(sa)
	if err != nil {
		t.Fatalf("missing interface index aborted the listener path: %v", err)
	}
	want := strconv.FormatUint(uint64(index), 10)
	if got.Zone != want {
		t.Fatalf("zone=%q want numeric %s", got.Zone, want)
	}
}

func TestUDPAddrFromSockaddrKeepsRealInterfaceIndex(t *testing.T) {
	ifi := firstInterface(t)
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[15] = 1
	sa := &unix.SockaddrInet6{Port: 9, Addr: addr, ZoneId: uint32(ifi.Index)}
	got, err := udpAddrFromSockaddr(sa)
	if err != nil {
		t.Fatal(err)
	}
	want := strconv.Itoa(ifi.Index)
	if got.Zone != want {
		t.Fatalf("zone=%q want numeric %s", got.Zone, want)
	}
}

func TestUDPAddrFromSockaddrIgnoresUnscoped(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1).To4()
	var addr [4]byte
	copy(addr[:], ip)
	sa := &unix.SockaddrInet4{Port: 9, Addr: addr}
	got, err := udpAddrFromSockaddr(sa)
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != "" || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("addr=%v", got)
	}
}
