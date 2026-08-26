//go:build unix

package quicopen

import (
	"context"
	"runtime"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestListenPacketAppliesLateBuffersUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenPacket(context.Background(), "udp4", "127.0.0.1:0", spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	if got := packetSockoptInt(t, sc, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after listenPacket", got)
	}
	if got := packetSockoptInt(t, sc, unix.SO_RCVBUF); got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after listenPacket", got)
	}
}

func TestListenPacketAppliesIPTTLUnix(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,ip-ttl=9")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenPacket(context.Background(), "udp4", "127.0.0.1:0", spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9", ttl)
	}
}

func TestListenPacketAppliesBroadcastUnix(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		wantOn bool
	}{
		{spec: "QUIC-LISTEN:0,broadcast", wantOn: true},
		{spec: "QUIC-LISTEN:0,so-broadcast", wantOn: true},
		{spec: "QUIC-LISTEN:0,broadcast=1", wantOn: true},
		{spec: "QUIC-LISTEN:0,broadcast=0", wantOn: false},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			pc, err := listenPacket(context.Background(), "udp4", "127.0.0.1:0", spec)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			sc, ok := pc.(syscall.Conn)
			if !ok {
				t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
			}
			got := packetSockoptInt(t, sc, unix.SO_BROADCAST)
			// Linux returns 1; Darwin/BSD return the so_options bit (0x20).
			if (got != 0) != tc.wantOn {
				t.Fatalf("SO_BROADCAST=%d want on=%v", got, tc.wantOn)
			}
		})
	}
}

func packetSockoptInt(t *testing.T, sc syscall.Conn, opt int) int {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}
