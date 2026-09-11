//go:build linux || darwin

package netopen

import (
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

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

func TestListenUDPAppendFcntlOnce(t *testing.T) {
	spec, err := parse.ParseSpec("UDP-RECV:0,bind=127.0.0.1,append")
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, mustAddr(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if n := countLifecycleOp(ops, "F_SETFL"); n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, ops)
	}
	if packetFcntlFlags(t, pc)&unix.O_APPEND == 0 {
		t.Fatal("UDP-RECV append did not set O_APPEND")
	}
}

func countLifecycleOp(ops []string, want string) int {
	n := 0
	for _, op := range ops {
		if op == want {
			n++
		}
	}
	return n
}

func packetFcntlFlags(t *testing.T, sc syscall.Conn) int {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := raw.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal(ferr)
	}
	return flags
}
