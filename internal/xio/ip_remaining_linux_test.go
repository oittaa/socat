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
