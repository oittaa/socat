package netopen

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPPeerIPv6AddrMapsIPv4(t *testing.T) {
	addr, zone, err := udpPeerIPv6Addr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	want := [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}
	if addr != want {
		t.Fatalf("mapped=%v want %v", addr, want)
	}
	if zone != 0 {
		t.Fatalf("zone=%d want 0", zone)
	}

	mapped := net.ParseIP("::ffff:192.0.2.1")
	addr, zone, err = udpPeerIPv6Addr(&net.UDPAddr{IP: mapped, Port: 53, Zone: "lo"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr[:], mapped.To16()) {
		t.Fatalf("v4-mapped=%v want %v", addr, mapped.To16())
	}
	if zone != 0 {
		t.Fatalf("v4-mapped zone=%d want 0", zone)
	}
}

func TestUDPPeerIPv4AddrRejectsIPv6(t *testing.T) {
	_, err := udpPeerIPv4Addr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9})
	if err == nil {
		t.Fatal("IPv6 peer on IPv4 socket must fail")
	}
}

func TestConnectUDPPeerIPv4OnDualStack(t *testing.T) {
	spec, err := parse.ParseSpec("UDP-LISTEN:0")
	if err != nil {
		t.Fatal(err)
	}
	laddr, err := xio.ResolveUDPAddr(context.Background(), spec, "udp", "[::]:0")
	if err != nil {
		t.Skipf("resolve [::]: %v", err)
	}
	pc, err := listenUDP("udp", laddr, spec)
	if err != nil {
		t.Skipf("dual-stack UDP listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if ip := pc.LocalAddr().(*net.UDPAddr).IP; ip.To4() != nil {
		t.Skip("did not get an IPv6 UDP socket")
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if err := connectUDPPeer(pc, peer); err != nil {
		t.Fatalf("connect IPv4 peer on dual-stack UDP: %v", err)
	}
}
