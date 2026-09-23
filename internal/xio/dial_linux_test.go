//go:build linux

package xio

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestTCP6LinkLocalZoneRoundTrip(t *testing.T) {
	host := linkLocalHost(t)
	cases := []struct {
		name    string
		lowport bool
	}{
		{name: "dial"},
		{name: "lowport", lowport: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lowport && os.Geteuid() != 0 {
				t.Skip("requires root (CAP_NET_BIND_SERVICE) to bind a port in 640-1023")
			}
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
			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

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

			spec := "TCP6:[" + host + "]:" + port
			var bind addrconfig.Address
			if tc.lowport {
				spec += ",bind=[" + host + "],lowport"
				parsed, err := parse.ParseSpec(spec)
				if err != nil {
					t.Fatal(err)
				}
				bind = mustDecodeAddress(t, parsed)
			}
			c, err := DialTCPAll(t.Context(), dialTargetFromText("tcp6", "["+host+"]", port), bind, nil, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if tc.lowport {
				local, ok := c.LocalAddr().(*net.TCPAddr)
				if !ok || local.Port < LowportMin || local.Port > LowportMax {
					t.Fatalf("local addr %v want a port in %d-%d", c.LocalAddr(), LowportMin, LowportMax)
				}
			}
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
		})
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
