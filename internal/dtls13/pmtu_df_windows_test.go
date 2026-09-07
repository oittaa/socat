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

func mtuDiscoverState(t *testing.T, conn *net.UDPConn, ipv6 bool) (int, error) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	level, opt := windows.IPPROTO_IP, windows.IP_MTU_DISCOVER
	if ipv6 {
		level, opt = windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER
	}
	var mode int
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		mode, ctrlErr = windows.GetsockoptInt(windows.Handle(fd), level, opt)
	}); err != nil {
		t.Fatal(err)
	}
	return mode, ctrlErr
}

func TestUnfragmentedProbesPrefersPMTUDISCProbe(t *testing.T) {
	conn := testUDP(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	mode, err := mtuDiscoverState(t, conn, false)
	if err == nil && mode == windows.IP_PMTUDISC_DO {
		t.Fatal("IP_MTU_DISCOVER is PMTUDISC_DO")
	}
	if err == nil && mode == windows.IP_PMTUDISC_PROBE {
		return
	}
	if dontFragment(t, conn, false) == 0 {
		t.Fatalf("neither IP_PMTUDISC_PROBE nor IP_DONTFRAGMENT is set (discover err=%v mode=%d)", err, mode)
	}
}

func TestUnfragmentedProbesNeverSetsPMTUDISCDO(t *testing.T) {
	conn := testUDP(t)
	if _, err := enableUnfragmentedSends(conn); err != nil {
		t.Fatal(err)
	}
	mode, err := mtuDiscoverState(t, conn, false)
	if err != nil {
		t.Skip("IP_MTU_DISCOVER is not readable on this stack")
	}
	if mode == windows.IP_PMTUDISC_DO {
		t.Fatal("IP_MTU_DISCOVER is PMTUDISC_DO")
	}
}
