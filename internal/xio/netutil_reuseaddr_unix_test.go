//go:build unix

package xio

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func reuseaddrValue(t *testing.T, conn syscall.Conn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		v, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return v
}

func TestTCPListenSetsReuseaddrByDefault(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sc, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", ln)
	}
	if got := reuseaddrValue(t, sc); got != 1 {
		t.Fatalf("TCP SO_REUSEADDR=%d want 1", got)
	}
}

func TestUDPListenOmitsReuseaddrByDefault(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", pc)
	}
	if got := reuseaddrValue(t, sc); got != 0 {
		t.Fatalf("UDP SO_REUSEADDR=%d want 0", got)
	}
}

func TestUDPListenForkSetsReuseaddr(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,fork")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", pc)
	}
	if got := reuseaddrValue(t, sc); got != 1 {
		t.Fatalf("UDP,fork SO_REUSEADDR=%d want 1", got)
	}
}
