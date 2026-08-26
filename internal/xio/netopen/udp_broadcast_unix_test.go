//go:build unix

package netopen

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestListenUDPAppliesBroadcastUnix(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		wantOn bool
	}{
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast", wantOn: true},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast=1", wantOn: true},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,so-broadcast", wantOn: true},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast=0", wantOn: false},
		{spec: "UDP4-RECV:0,bind=127.0.0.1,broadcast=0", wantOn: false},
		{spec: "UDP4-RECVFROM:0,bind=127.0.0.1,broadcast", wantOn: true},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			assertBroadcast(t, packetSockoptInt(t, pc, unix.SO_BROADCAST), tc.wantOn)
		})
	}
}

func TestUDPDatagramAppliesBroadcastUnix(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		wantOn bool
	}{
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast", wantOn: true},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,so-broadcast", wantOn: true},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast=1", wantOn: true},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast=0", wantOn: false},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			cfg := udpListenConfig(spec)
			pc, err := cfg.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			sc, ok := pc.(syscall.Conn)
			if !ok {
				t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
			}
			assertBroadcast(t, packetSockoptInt(t, sc, unix.SO_BROADCAST), tc.wantOn)
		})
	}
}

// Linux getsockopt(SO_BROADCAST) returns 1; Darwin/BSD return the so_options
// bit (SO_BROADCAST is 0x20). Treat any non-zero as enabled.
func assertBroadcast(t *testing.T, got int, wantOn bool) {
	t.Helper()
	if (got != 0) != wantOn {
		t.Fatalf("SO_BROADCAST=%d want on=%v", got, wantOn)
	}
}
