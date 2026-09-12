//go:build linux || darwin

package xio

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestListenControlAppliesMulticastTTL(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-multicast-ttl=4,mcloop")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(mustDecodeAddress(t, spec))}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL); got != 4 {
		t.Fatalf("ListenControl IP_MULTICAST_TTL=%d want 4", got)
	}
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP); got != 1 {
		t.Fatalf("ListenControl IP_MULTICAST_LOOP=%d want 1 (bare flag)", got)
	}
}

func TestDialControlAppliesIPv6MulticastLoop(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-multicast-loop=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP); got != 0 {
		t.Fatalf("IPV6_MULTICAST_LOOP=%d want 0", got)
	}
}

func TestIPv4SocketRejectsIPv6MulticastLoop(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ipv6-multicast-loop=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported on IPv4") {
		t.Fatalf("error=%v want not supported on IPv4", err)
	}
}

func TestIPv6RecvErrRejectedAtOpenSpecAndDialControl(t *testing.T) {
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-recverr")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRecvErr(mustDecodeAddress(t, spec)); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("RejectUnsupportedRecvErr=%v", err)
	}
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "MSG_ERRQUEUE") {
		t.Fatalf("DialControl ipv6-recverr=%v want MSG_ERRQUEUE rejection", err)
	}
}

func udpLevelSockoptInt(t *testing.T, uc *net.UDPConn, level, opt int) int {
	t.Helper()
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), level, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}
