//go:build linux

package xio

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestDialControlAppliesIPRetopts(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-retopts")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_RETOPTS); got != 1 {
		t.Fatalf("IP_RETOPTS=%d want 1", got)
	}
}

func TestDialControlAppliesIPRetoptsZero(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-retopts=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_RETOPTS); got != 0 {
		t.Fatalf("IP_RETOPTS=%d want 0", got)
	}
}

func TestDialControlRejectsRouterAlertOnUDP(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("err=%v want address type", err)
	}
}

func TestApplyRouterAlertOnRawICMP(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, syscall.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("SOCK_RAW requires CAP_NET_RAW: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:1,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPastSocketPhase(fd, spec, "ip4"); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_ROUTER_ALERT)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("IP_ROUTER_ALERT=%d want 1", got)
	}
}

func TestApplyRouterAlertRejectsIPPROTORaw(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, syscall.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("SOCK_RAW requires CAP_NET_RAW: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:255,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyPastSocketPhase(fd, spec, "ip4")
	if err == nil || !strings.Contains(err.Error(), "IPPROTO_RAW") {
		t.Fatalf("err=%v want IPPROTO_RAW", err)
	}
}

func TestLinuxGetOnlyIPKernelIsNotSettable(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU, 1500); !errors.Is(err, unix.ENOPROTOOPT) {
		t.Fatalf("IP_MTU SET err=%v want ENOPROTOOPT", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTOPTIONS, 1); !errors.Is(err, unix.ENOPROTOOPT) {
		t.Fatalf("IP_PKTOPTIONS SET err=%v want ENOPROTOOPT", err)
	}
	sa := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Connect(fd, sa); err != nil {
		t.Fatal(err)
	}
	mtu, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU)
	if err != nil {
		t.Fatalf("IP_MTU GET on connected UDP: %v", err)
	}
	if mtu <= 0 {
		t.Fatalf("IP_MTU GET=%d want positive path MTU", mtu)
	}
	if _, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTOPTIONS); !errors.Is(err, unix.ENOPROTOOPT) {
		t.Fatalf("IP_PKTOPTIONS GET on UDP err=%v want ENOPROTOOPT", err)
	}
}

func TestApplyGetOnlyIPOption(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-mtu")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "get-only") {
		t.Fatalf("err=%v want get-only", err)
	}
}
