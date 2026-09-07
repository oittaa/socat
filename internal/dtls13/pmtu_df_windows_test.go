//go:build windows

package dtls13

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func dontFragment(t *testing.T, conn *net.UDPConn, ipv6 bool) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	level, opt := windows.IPPROTO_IP, windowsIPDontFragment
	if ipv6 {
		level, opt = windows.IPPROTO_IPV6, windowsIPv6DontFrag
	}
	var mode int
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		mode, ctrlErr = windows.GetsockoptInt(windows.Handle(fd), level, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if ctrlErr != nil {
		t.Fatal(ctrlErr)
	}
	return mode
}

func TestUnfragmentedProbesSetsDontFragment(t *testing.T) {
	conn := testUDP(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	if dontFragment(t, conn, false) == 0 {
		t.Fatal("IP_DONTFRAGMENT is not set")
	}
}
