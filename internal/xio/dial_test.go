package xio

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func DialTargetFromText(network, host, port string) DialTarget {
	return DialTarget{Network: network, Host: addrconfig.HostFromText(host), Port: addrconfig.PortFromText(port)}
}

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
	n, err = ResolvePort("tcp", addrconfig.PortFromText("080"))
	if err != nil || n != 80 {
		t.Fatalf("prepared numeric: %d %v", n, err)
	}
}

func TestConnectNetworkPreferDualStack(t *testing.T) {
	g := &Global{IPVersion: IPv6}
	s := parse.Spec{Type: "TCP"}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), addrconfig.HostFromText("example.com"), "tcp"); n != "tcp" {
		t.Fatalf("generic TCP want tcp got %s", n)
	}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), addrconfig.HostFromText("example.com"), "tcp4"); n != "tcp4" {
		t.Fatalf("TCP4 forced want tcp4 got %s", n)
	}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), addrconfig.HostFromText("[::ffff:127.0.0.1]"), "tcp"); n != "tcp4" {
		t.Fatalf("generic TCP mapped literal want tcp4 got %s", n)
	}
	s.Options = []parse.Option{{Name: "pf", Value: "ip4", Has: true}}
	if n := ConnectNetworkForType(g, mustDecodeAddress(t, s), addrconfig.HostFromText("example.com"), "tcp"); n != "tcp4" {
		t.Fatalf("pf=ip4 want tcp4 got %s", n)
	}
	mapped := addrconfig.HostFromText("[::ffff:127.0.0.1]")
	if n := ConnectNetworkForType(g, addrconfig.Address{}, mapped, "tcp"); n != "tcp4" {
		t.Fatalf("proxy mapped server want tcp4 got %s", n)
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
	_, err = DialTCPAll(ctx, DialTargetFromText("tcp4", "127.0.0.1", "1"), mustDecodeAddress(t, s), nil, time.Second, nil)
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

func TestResolveDialIPsRejectsTCP6IPv4Literals(t *testing.T) {
	ctx := context.Background()
	config := mustDecodeAddress(t, parse.Spec{Type: "TCP6"})
	for _, host := range []string{"127.0.0.1", "[::ffff:127.0.0.1]"} {
		_, err := ResolveDialIPs(ctx, DialTargetFromText("tcp6", host, "9"), config, nil)
		if err == nil || !strings.Contains(err.Error(), "not IPv6") {
			t.Fatalf("%s: err=%v want not IPv6", host, err)
		}
	}
}

func TestDialTCP6IPv4LiteralDoesNotConnect(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	config := mustDecodeAddress(t, parse.Spec{Type: "TCP6"})
	for _, host := range []string{"127.0.0.1", "[::ffff:127.0.0.1]"} {
		c, err := DialTCPAll(ctx, DialTargetFromText("tcp6", host, port), config, nil, time.Second, nil)
		if err == nil {
			_ = c.Close()
			t.Fatalf("%s: connected over IPv4; want not IPv6", host)
		}
		if !strings.Contains(err.Error(), "not IPv6") {
			t.Fatalf("%s: err=%v want not IPv6", host, err)
		}
	}
}

func TestBindTCPAddrEmbeddedPortOverridesSourcePort(t *testing.T) {
	s, err := parse.ParseSpec("TCP4:127.0.0.1:9,bind=127.0.0.1:123,sourceport=9")
	if err != nil {
		t.Fatal(err)
	}
	laddr, skip, err := BindTCPAddrForRemote(t.Context(), net.IPv4(127, 0, 0, 1), mustDecodeAddress(t, s), "tcp4")
	if err != nil || skip || laddr == nil {
		t.Fatalf("laddr=%v skip=%v err=%v", laddr, skip, err)
	}
	if laddr.Port != 123 {
		t.Fatalf("port=%d want 123 from bind=host:port, not sourceport", laddr.Port)
	}
	if !laddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("ip=%v", laddr.IP)
	}
}

func TestBindTCPAddrSourcePortWhenBindHasNoPort(t *testing.T) {
	s, err := parse.ParseSpec("TCP4:127.0.0.1:9,bind=127.0.0.1,sourceport=123")
	if err != nil {
		t.Fatal(err)
	}
	laddr, skip, err := BindTCPAddrForRemote(t.Context(), net.IPv4(127, 0, 0, 1), mustDecodeAddress(t, s), "tcp4")
	if err != nil || skip || laddr == nil {
		t.Fatalf("laddr=%v skip=%v err=%v", laddr, skip, err)
	}
	if laddr.Port != 123 {
		t.Fatalf("port=%d want sourceport 123", laddr.Port)
	}
}

func decodeConnectBind(t *testing.T, raw string) addrconfig.Address {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type, Role: addrconfig.AddressRoleConnect, Family: addrconfig.IPFamilyIPv4})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestBindTCPAddrEmptyHostSelectsPassiveDefault(t *testing.T) {
	config := decodeConnectBind(t, "TCP4:127.0.0.1:9,bind=:1234")
	laddr, skip, err := BindTCPAddrForRemote(t.Context(), net.IPv4(127, 0, 0, 1), config, "tcp4")
	if err != nil || skip || laddr == nil {
		t.Fatalf("laddr=%v skip=%v err=%v", laddr, skip, err)
	}
	if laddr.Port != 1234 || !laddr.IP.Equal(net.IPv4zero) {
		t.Fatalf("passive bind=:port got %v", laddr)
	}

	config = decodeConnectBind(t, "TCP4:127.0.0.1:9,bind=:1234,ai-passive=0")
	laddr, skip, err = BindTCPAddrForRemote(t.Context(), net.IPv4(127, 0, 0, 1), config, "tcp4")
	if err != nil || skip || laddr == nil {
		t.Fatalf("laddr=%v skip=%v err=%v", laddr, skip, err)
	}
	if laddr.Port != 1234 || !laddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("ai-passive=0 bind=:port got %v", laddr)
	}
}

func TestBindTCPAddrEmptyHostPortZeroKeepsLoopback(t *testing.T) {
	config := decodeConnectBind(t, "TCP4:127.0.0.1:9,bind=:0,ai-passive=0")
	laddr, skip, err := BindTCPAddrForRemote(t.Context(), net.IPv4(127, 0, 0, 1), config, "tcp4")
	if err != nil || skip || laddr == nil {
		t.Fatalf("laddr=%v skip=%v err=%v want loopback:0", laddr, skip, err)
	}
	if laddr.Port != 0 || !laddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("ai-passive=0 bind=:0 got %v", laddr)
	}
}
