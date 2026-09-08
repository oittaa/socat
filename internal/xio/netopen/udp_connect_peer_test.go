package netopen

import (
	"net"
	"testing"
)

func TestUDPPeerIPv4AddrRejectsIPv6(t *testing.T) {
	_, err := udpPeerIPv4Addr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9})
	if err == nil {
		t.Fatal("IPv6 peer on IPv4 socket must fail")
	}
}
