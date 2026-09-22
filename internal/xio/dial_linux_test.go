//go:build linux

package xio

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestDialTCP6LinkLocalZoneNotInvalidArgument(t *testing.T) {
	ifi, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	c, err := DialTCPAll(ctx, DialTargetFromText("tcp6", "fe80::1%"+ifi.Name, "9"), addrconfig.Address{}, nil, 0, nil)
	if err == nil {
		_ = c.Close()
		return
	}
	if errors.Is(err, syscall.EINVAL) {
		t.Fatalf("link-local dial dropped the zone: %v", err)
	}
}

func TestTCP6LinkLocalZoneRoundTrip(t *testing.T) {
	host := linkLocalHost(t)
	config := decodeListen(t, "TCP6-LISTEN:0,bind=["+host+"]")
	addr, err := TCPListenAddress(t.Context(), config, "tcp6", config.Network.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	gotHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != host {
		t.Fatalf("listen address %q want host %s", addr, host)
	}

	ln, err := ListenTCP(t.Context(), config, "tcp6", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			accepted <- err
			return
		}
		if string(buf) != "ping" {
			accepted <- errors.New("payload " + string(buf))
			return
		}
		_, err = c.Write([]byte("pong"))
		accepted <- err
	}()

	c, err := DialTCPAll(t.Context(), DialTargetFromText("tcp6", "["+host+"]", strconv.Itoa(port)), addrconfig.Address{}, nil, 0, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("reply %q", buf)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func linkLocalHost(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP == nil || !ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			ip := ipn.IP.To16()
			if ip == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			return addr.WithZone(ifi.Name).String()
		}
	}
	t.Skip("no IPv6 link-local address on an up interface")
	return ""
}
