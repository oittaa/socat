//go:build linux

package dtls13

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func testUDP6(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func mtuDiscoverMode(t *testing.T, conn *net.UDPConn, ipv6 bool) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	level, opt := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
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

func ipv4MTUDiscoverMode(t *testing.T, conn *net.UDPConn) int {
	return mtuDiscoverMode(t, conn, false)
}

func TestUnfragmentedProbesUsesPMTUDISCProbe(t *testing.T) {
	conn := testUDP(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	mode := ipv4MTUDiscoverMode(t, conn)
	if mode != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("IP_MTU_DISCOVER=%d want PMTUDISC_PROBE=%d (not DO=%d)", mode, unix.IP_PMTUDISC_PROBE, unix.IP_PMTUDISC_DO)
	}
}

func TestUnfragmentedProbesIPv6UsesPMTUDISCProbe(t *testing.T) {
	conn := testUDP6(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	mode := mtuDiscoverMode(t, conn, true)
	if mode != unix.IPV6_PMTUDISC_PROBE {
		t.Fatalf("IPV6_MTU_DISCOVER=%d want PMTUDISC_PROBE=%d (not DO=%d)", mode, unix.IPV6_PMTUDISC_PROBE, unix.IPV6_PMTUDISC_DO)
	}
}

func TestUnfragmentedProbesDefaultOff(t *testing.T) {
	client, _, _ := connectionPair(t)
	if client.transport.unfragmented || client.session.working.canProbe {
		t.Fatal("default client enabled DF probes")
	}
	if ipv4MTUDiscoverMode(t, client.transport.udp) == unix.IP_PMTUDISC_PROBE {
		t.Fatal("default client socket is PMTUDISC_PROBE")
	}
}
