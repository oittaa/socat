//go:build unix

package xio

import (
	"context"
	"fmt"
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

func reuseaddrEnabled(t *testing.T, conn syscall.Conn) bool {
	t.Helper()
	// Linux returns 1; Darwin has been observed to return 4 when the option is on.
	return reuseaddrValue(t, conn) != 0
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
	if !reuseaddrEnabled(t, sc) {
		t.Fatal("TCP listen did not set SO_REUSEADDR")
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
	if reuseaddrEnabled(t, sc) {
		t.Fatal("UDP listen set SO_REUSEADDR without fork or reuseaddr")
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
	if !reuseaddrEnabled(t, sc) {
		t.Fatal("UDP-LISTEN,fork did not set SO_REUSEADDR")
	}
}

func TestUDPRecvfromForkOmitsReuseaddr(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,fork")
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
	if reuseaddrEnabled(t, sc) {
		t.Fatal("UDP4-RECVFROM,fork set SO_REUSEADDR")
	}
}

func TestQUICListenForkOmitsReuseaddr(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,bind=127.0.0.1,fork")
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
	if reuseaddrEnabled(t, sc) {
		t.Fatal("QUIC-LISTEN,fork set SO_REUSEADDR")
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	secondSpec, err := parse.ParseSpec(fmt.Sprintf("QUIC-LISTEN:%d,bind=127.0.0.1,fork", port))
	if err != nil {
		t.Fatal(err)
	}
	secondLC := net.ListenConfig{Control: ListenControl(secondSpec)}
	second, err := secondLC.ListenPacket(context.Background(), "udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err == nil {
		_ = second.Close()
		t.Fatal("second QUIC-LISTEN,fork bound successfully")
	}
}
