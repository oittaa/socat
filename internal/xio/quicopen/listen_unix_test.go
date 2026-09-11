//go:build linux || darwin

package quicopen

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestListenPacketAppliesSetsockoptUnix(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("QUIC-LISTEN:0,setsockopt=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenPacket(context.Background(), "udp4", addrconfig.HostFromText("127.0.0.1"), addrconfig.PortFromText("0"), mustAddr(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	if got := packetSockoptInt(t, sc, unix.SO_KEEPALIVE); got == 0 {
		// Darwin getsockopt returns the so_options bit (8), not 1.
		t.Fatalf("SO_KEEPALIVE=%d want enabled after listenPacket setsockopt", got)
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
