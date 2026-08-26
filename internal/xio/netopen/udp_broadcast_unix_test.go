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
		spec string
		want int
	}{
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast", want: 1},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast=1", want: 1},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,so-broadcast", want: 1},
		{spec: "UDP4-LISTEN:0,bind=127.0.0.1,broadcast=0", want: 0},
		{spec: "UDP4-RECV:0,bind=127.0.0.1,broadcast=0", want: 0},
		{spec: "UDP4-RECVFROM:0,bind=127.0.0.1,broadcast", want: 1},
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
			if got := packetSockoptInt(t, pc, unix.SO_BROADCAST); got != tc.want {
				t.Fatalf("SO_BROADCAST=%d want %d", got, tc.want)
			}
		})
	}
}

func TestUDPDatagramAppliesBroadcastUnix(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want int
	}{
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast", want: 1},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,so-broadcast", want: 1},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast=1", want: 1},
		{spec: "UDP-DATAGRAM:127.0.0.1:9,broadcast=0", want: 0},
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
			if got := packetSockoptInt(t, sc, unix.SO_BROADCAST); got != tc.want {
				t.Fatalf("SO_BROADCAST=%d want %d", got, tc.want)
			}
		})
	}
}
