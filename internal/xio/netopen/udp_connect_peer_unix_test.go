//go:build linux || darwin

package netopen

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUDPPeerSockaddrUsesSocketFamily(t *testing.T) {
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("udp6 listen: %v", err)
	}
	t.Cleanup(func() { _ = v6.Close() })
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	var sa unix.Sockaddr
	raw, err := v6.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		sa, cerr = udpPeerSockaddr(int(fd), peer)
	}); err != nil {
		t.Fatal(err)
	}
	if cerr != nil {
		t.Fatal(cerr)
	}
	inet6, ok := sa.(*unix.SockaddrInet6)
	if !ok {
		t.Fatalf("IPv4 peer on AF_INET6: %T want SockaddrInet6", sa)
	}
	want := net.IPv4(192, 0, 2, 1).To16()
	if inet6.Addr != [16]byte(want) {
		t.Fatalf("addr=%v want %v", inet6.Addr, want)
	}
	if inet6.Port != 53 {
		t.Fatalf("port=%d want 53", inet6.Port)
	}

	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v4.Close() })
	raw, err = v4.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		sa, cerr = udpPeerSockaddr(int(fd), peer)
	}); err != nil {
		t.Fatal(err)
	}
	if cerr != nil {
		t.Fatal(cerr)
	}
	inet4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		t.Fatalf("IPv4 peer on AF_INET: %T want SockaddrInet4", sa)
	}
	if inet4.Addr != [4]byte{192, 0, 2, 1} {
		t.Fatalf("addr=%v want 192.0.2.1", inet4.Addr)
	}
}
