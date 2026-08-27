//go:build linux

package xio

import (
	"context"
	"errors"
	"fmt"
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

func TestDialControlAppliesMTUDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		network string
		address string
		option  string
		level   int
		opt     int
	}{
		{name: "ipv4", network: "udp4", address: "127.0.0.1:9", option: "ip-mtu-discover=2", level: unix.IPPROTO_IP, opt: unix.IP_MTU_DISCOVER},
		{name: "ipv6", network: "udp6", address: "[::1]:9", option: "ipv6-mtu-discover=2", level: unix.IPPROTO_IPV6, opt: unix.IPV6_MTU_DISCOVER},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.network == "udp6" {
				skipWithoutIPv6Loopback(t)
			}
			spec, err := parse.ParseSpec("UDP:" + tt.address + "," + tt.option)
			if err != nil {
				t.Fatal(err)
			}
			d := &net.Dialer{Control: DialControl(spec, tt.network, nil)}
			c, err := d.Dial(tt.network, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			if got := udpLevelSockoptInt(t, c.(*net.UDPConn), tt.level, tt.opt); got != 2 {
				t.Fatalf("MTU discovery policy=%d want 2", got)
			}
		})
	}
}

func TestMTUDiscoveryOccurrencesPreserveOptionOrder(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-mtu-discover=0,ip-multicast-ttl=9,mtudiscover=2")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	restore := SetSockoptTestHook(func(call SockoptCall) {
		switch {
		case call.AsInt && call.Level == unix.IPPROTO_IP && call.Opt == unix.IP_MTU_DISCOVER:
			got = append(got, fmt.Sprintf("mtu=%d", call.IntValue))
		case !call.AsInt && call.Level == unix.IPPROTO_IP && call.Opt == unix.IP_MULTICAST_TTL:
			got = append(got, fmt.Sprintf("ttl=%d", call.Bytes[0]))
		}
	})
	t.Cleanup(restore)
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	want := "[mtu=0 ttl=9 mtu=2]"
	if fmt.Sprint(got) != want {
		t.Fatalf("setsockopt order=%v want %s", got, want)
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
