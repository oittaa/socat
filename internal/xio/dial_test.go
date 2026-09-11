package xio

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestResolvePortNumSCTPFallsBackToTCP(t *testing.T) {
	n, err := ResolvePortNum("sctp4", "http")
	if err != nil {
		t.Fatal(err)
	}
	if n != 80 {
		t.Fatalf("got %d", n)
	}
	n, err = ResolvePortNum("sctp", "443")
	if err != nil || n != 443 {
		t.Fatalf("numeric: %d %v", n, err)
	}
}

func TestConnectNetworkPreferDualStack(t *testing.T) {
	g := &Global{IPVersion: IPv6}
	s := parse.Spec{Type: "TCP"}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), "example.com", "tcp"); n != "tcp" {
		t.Fatalf("generic TCP want tcp got %s", n)
	}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), "example.com", "tcp4"); n != "tcp4" {
		t.Fatalf("TCP4 forced want tcp4 got %s", n)
	}
	s.Options = []parse.Option{{Name: "pf", Value: "ip4", Has: true}}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), "example.com", "tcp"); n != "tcp4" {
		t.Fatalf("pf=ip4 want tcp4 got %s", n)
	}
}

func TestResolveOrderIPv6First(t *testing.T) {
	ctx := context.Background()
	g := &Global{IPVersion: IPv6}
	s := parse.Spec{}
	ips, err := resolveConnectIPs(ctx, "tcp", "localhost", mustDecodeAddress(t, s), g)
	if err != nil {
		t.Skip(err)
	}
	if len(ips) < 2 {
		t.Skip("localhost not dual-stack")
	}
	if ips[0].To4() != nil {
		t.Fatalf("with -6 preference first IP should be v6, got %v", ips)
	}
}

func TestDialTCPLowportReturnsConnectErrorWhenBindSucceeds(t *testing.T) {
	if lowportWildcardBindDenied() {
		t.Skip("cannot bind lowport; fail-closed path is covered separately")
	}
	s, err := parse.ParseSpec("TCP4:127.0.0.1:1,lowport")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = DialTCPAll(ctx, DialTarget{Network: "tcp4", Host: "127.0.0.1", Port: "1"}, mustDecodeAddress(t, s), nil, time.Second, nil)
	if err == nil {
		t.Fatal("expected connect error after a successful lowport bind")
	}
	if strings.Contains(err.Error(), "lowport: cannot bind a port in 640-1023") {
		t.Fatalf("bind succeeded but error was wrapped as fail-closed: %v", err)
	}
}

// lowportWildcardBindDenied reports whether binding 0.0.0.0:1023 is denied
// with EACCES/EPERM, matching dialTCPLowport's fail-closed condition.
func lowportWildcardBindDenied() bool {
	d := net.Dialer{
		Timeout:   200 * time.Millisecond,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: 1023},
	}
	c, err := d.Dial("tcp4", "127.0.0.1:1")
	if err == nil {
		_ = c.Close()
		return false
	}
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}
