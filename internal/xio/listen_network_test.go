package xio_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
	"github.com/oittaa/socat/internal/xio/tlsopen"

	"github.com/oittaa/socat/internal/parse"
)

func TestListenNetworkPrecedence(t *testing.T) {
	// Clean env for deterministic defaults.
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "")

	// Default → tcp4
	if got := xio.ListenNetwork(&xio.Global{}, parse.Spec{}); got != "tcp4" {
		t.Fatalf("default: got %q want tcp4", got)
	}

	// Env SOCAT_DEFAULT_LISTEN_IP=6 → tcp6
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	if got := xio.ListenNetwork(&xio.Global{}, parse.Spec{}); got != "tcp6" {
		t.Fatalf("env=6: got %q want tcp6", got)
	}
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "4")
	if got := xio.ListenNetwork(&xio.Global{}, parse.Spec{}); got != "tcp4" {
		t.Fatalf("env=4: got %q want tcp4", got)
	}

	// xio.Global -6 overrides env=4
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "4")
	if got := xio.ListenNetwork(&xio.Global{IPVersion: xio.IPv6}, parse.Spec{}); got != "tcp6" {
		t.Fatalf("-6: got %q want tcp6", got)
	}

	// pf= overrides global and env
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	s := parse.Spec{Options: []parse.Option{{Name: "pf", Value: "ip4", Has: true}}}
	if got := xio.ListenNetwork(&xio.Global{IPVersion: xio.IPv6}, s); got != "tcp4" {
		t.Fatalf("pf=ip4: got %q want tcp4", got)
	}
	s = parse.Spec{Options: []parse.Option{{Name: "pf", Value: "ip6", Has: true}}}
	if got := xio.ListenNetwork(&xio.Global{IPVersion: xio.IPv4}, s); got != "tcp6" {
		t.Fatalf("pf=ip6: got %q want tcp6", got)
	}

	// -0 → dual-stack "tcp"
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "4")
	if got := xio.ListenNetwork(&xio.Global{IPVersion: xio.IPvAny}, parse.Spec{}); got != "tcp" {
		t.Fatalf("-0: got %q want tcp", got)
	}
}

func TestVersionFromPF(t *testing.T) {
	cases := []struct {
		in      string
		want    xio.IPVersion
		wantOK  bool
		network string
	}{
		{"ip4", xio.IPv4, true, "tcp4"},
		{"IPv4", xio.IPv4, true, "tcp4"},
		{"inet", xio.IPv4, true, "tcp4"},
		{"4", xio.IPv4, true, "tcp4"},
		{"2", xio.IPv4, true, "tcp4"},
		{"ip6", xio.IPv6, true, "tcp6"},
		{"INET6", xio.IPv6, true, "tcp6"},
		{"10", xio.IPv6, true, "tcp6"},
		{"unix", 0, false, ""},
		{"", 0, false, ""},
	}
	for _, tc := range cases {
		got, ok := xio.VersionFromPF(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("VersionFromPF(%q)=%v,%v want %v,%v", tc.in, got, ok, tc.want, tc.wantOK)
		}
		if n := xio.NetworkFromPF(tc.in, "tcp", "fallback"); tc.wantOK {
			if n != tc.network {
				t.Errorf("NetworkFromPF(%q)=%q want %q", tc.in, n, tc.network)
			}
		} else if n != "fallback" {
			t.Errorf("NetworkFromPF(%q)=%q want fallback", tc.in, n)
		}
	}
	if n := xio.NetworkFromPF("ip4", "udp", ""); n != "udp4" {
		t.Fatalf("udp pf: got %q", n)
	}
	if n := xio.NetworkFromPF("6", "ip", ""); n != "ip6" {
		t.Fatalf("ip pf: got %q", n)
	}
}

func TestTLSListenHonorsDefaultListenIP6(t *testing.T) {
	// TLS-LISTEN without pf= must follow SOCAT_DEFAULT_LISTEN_IP like TCP-LISTEN.
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln0, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	port := ln0.Addr().(*net.TCPAddr).Port
	_ = ln0.Close()

	certPath, err := tlsopen.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := parse.Spec{
		Type:   "TLS-LISTEN",
		Params: []string{strconv.Itoa(port)},
		Options: []parse.Option{
			{Name: "reuseaddr"},
			{Name: "fork"}, // return Listener without blocking on Accept
			{Name: "verify", Value: "0", Has: true},
			{Name: "cert", Value: certPath, Has: true},
		},
	}
	o, err := xio.OpenSpec(ctx, s, xio.ModeRead, &xio.Global{})
	if err != nil {
		t.Fatalf("open TLS-LISTEN: %v", err)
	}
	defer func() {
		if o != nil {
			_ = o.Close()
		}
	}()
	if o.Listener == nil {
		t.Fatal("expected Listener in fork mode")
	}

	// Listener must be IPv6 (or dual-stack on ::) — not 0.0.0.0.
	addr := o.Listener.Addr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		t.Fatalf("expected IPv6 listen addr with SOCAT_DEFAULT_LISTEN_IP=6, got %q", addr)
	}
}
