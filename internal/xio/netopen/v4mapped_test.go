package netopen

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestDialUDP6V4MappedConnects(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := ln.ReadFrom(buf)
		done <- err
	}()

	dns := startARecordDNS(t)
	s := parse.Spec{Type: "UDP6", Options: []parse.Option{
		{Name: "res-nsaddr", Value: dns.addr, Has: true},
		{Name: "ai-v4mapped"},
	}}
	c, err := dialUDPForSpec(t.Context(), "udp6", nil, net.JoinHostPort("udp6-v4mapped.test", strconv.Itoa(ln.LocalAddr().(*net.UDPAddr).Port)), s, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if ua, ok := c.LocalAddr().(*net.UDPAddr); !ok || ua.IP.To4() == nil {
		t.Fatalf("UDP6+ai-v4mapped local %v want IPv4 socket", c.LocalAddr())
	}
	if err := <-done; err != nil {
		t.Fatalf("udp4 listener did not receive UDP6+ai-v4mapped payload: %v", err)
	}
}

func TestDialUDP6V4MappedBindHostnameConnects(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := ln.ReadFrom(buf)
		done <- err
	}()

	dns := startARecordDNS(t)
	port := strconv.Itoa(ln.LocalAddr().(*net.UDPAddr).Port)
	spec, err := parse.ParseSpec(
		"UDP6:udp6-v4mapped-bind.test:" + port +
			",ai-v4mapped,bind=udp6-v4mapped-bind.test,res-nsaddr=" + dns.addr,
	)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openUDP6Connect(t.Context(), spec, xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if _, err := opened.Stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if local, ok := opened.Stream.(interface{ LocalAddr() net.Addr }); !ok {
		t.Fatalf("stream %T has no LocalAddr", opened.Stream)
	} else if ua, ok := local.LocalAddr().(*net.UDPAddr); !ok || ua.IP.To4() == nil {
		t.Fatalf("UDP6+ai-v4mapped,bind=hostname local %v want IPv4 socket", local.LocalAddr())
	}
	if err := <-done; err != nil {
		t.Fatalf("udp4 listener did not receive mapped UDP bind-hostname payload: %v", err)
	}
}

func TestDialUDP6IPv4LiteralKeepsFamily(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := parse.Spec{Type: "UDP6", Options: []parse.Option{{Name: "ai-v4mapped"}}}
	_, err = dialUDPForSpec(t.Context(), "udp6", nil, ln.LocalAddr().String(), s, nil, time.Second)
	if err == nil {
		t.Fatal("UDP6 to an IPv4 literal succeeded; want family mismatch")
	}
}

func TestRawIP6MappedHostnameSwitchesToIPv4(t *testing.T) {
	mapped := net.ParseIP("::ffff:192.0.2.1")
	network := xio.DialNetwork("ip6", mapped)
	if network != "ip4" {
		t.Fatalf("DialNetwork=%s want ip4", network)
	}
	raddr := &net.IPAddr{IP: mapped.To4()}
	if err := requireRawIPFamily("IP6-SENDTO", network, raddr, "raw-v4mapped.test"); err != nil {
		t.Fatal(err)
	}
	if err := requireRawIPFamily("IP6-SENDTO", "ip6", &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}, "192.0.2.1"); err == nil {
		t.Fatal("IP6-SENDTO IPv4 literal: want family mismatch")
	}
}

func TestRawIP6V4MappedHostnameResolves(t *testing.T) {
	dns := startARecordDNS(t)
	s := parse.Spec{Type: "IP6-SENDTO", Options: []parse.Option{
		{Name: "res-nsaddr", Value: dns.addr, Has: true},
		{Name: "ai-v4mapped"},
	}}
	addr, err := resolveRawIPTarget(t.Context(), s, "ip6", "raw6-v4mapped.test")
	if err != nil {
		t.Fatal(err)
	}
	if addr.IP.To4() == nil {
		t.Fatalf("IP6-SENDTO+ai-v4mapped resolved %v want IPv4-mapped", addr.IP)
	}
	network := xio.DialNetwork("ip6", addr.IP)
	if network != "ip4" {
		t.Fatalf("DialNetwork=%s want ip4", network)
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		addr = &net.IPAddr{IP: ip4}
	}
	if err := requireRawIPFamily("IP6-SENDTO", network, addr, "raw6-v4mapped.test"); err != nil {
		t.Fatal(err)
	}
}
