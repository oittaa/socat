//go:build darwin

package dtls13

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func dontFrag(t *testing.T, conn *net.UDPConn, ipv6 bool) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	level, opt := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	var mode int
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		mode, ctrlErr = unix.GetsockoptInt(int(fd), level, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if ctrlErr != nil {
		t.Fatal(ctrlErr)
	}
	return mode
}

func TestUnfragmentedProbesSetsIPv4DontFrag(t *testing.T) {
	conn := testUDP(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	if dontFrag(t, conn, false) != 1 {
		t.Fatal("IP_DONTFRAG is not set")
	}
}
