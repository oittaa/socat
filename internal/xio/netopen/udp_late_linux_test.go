//go:build linux

package netopen

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestListenUDPAppliesLateBuffers(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, mustAddr(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if got := packetSockoptInt(t, pc, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after listenUDP", got)
	}
	if got := packetSockoptInt(t, pc, unix.SO_RCVBUF); got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after listenUDP", got)
	}
}
