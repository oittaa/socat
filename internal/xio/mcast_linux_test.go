//go:build linux

package xio

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestDialControlAppliesFreebind(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-freebind")
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
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_FREEBIND); got != 1 {
		t.Fatalf("IP_FREEBIND=%d want 1", got)
	}
}

func TestListenControlAppliesTransparentOrReportsEPERM(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,ip-transparent")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		if !errors.Is(err, unix.EPERM) && !errors.Is(err, syscall.EPERM) && !strings.Contains(err.Error(), "ip-transparent") {
			t.Fatalf("error=%v want ip-transparent kernel error", err)
		}
		return
	}
	t.Cleanup(func() { _ = ln.Close() })
	raw, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("listener %T is not syscall.Conn", ln)
	}
	sc, err := raw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = sc.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if v != 1 {
		t.Fatalf("IP_TRANSPARENT=%d want 1", v)
	}
}
