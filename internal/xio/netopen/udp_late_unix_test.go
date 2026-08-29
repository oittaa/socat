//go:build linux || darwin

package netopen

import (
	"net"
	"runtime"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestListenUDPAppliesLateBuffersUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
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

func TestDialUDPSessionAppliesLateUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,fork,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	uc, err := dialUDPSession(t.Context(), "udp4", local, peer.LocalAddr().(*net.UDPAddr), spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	if got := packetSockoptInt(t, uc, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after dialUDPSession", got)
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

func TestListenUDPAppendFcntlOnce(t *testing.T) {
	spec, err := parse.ParseSpec("UDP-RECV:0,bind=127.0.0.1,append")
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
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
