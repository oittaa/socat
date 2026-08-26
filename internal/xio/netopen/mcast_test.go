//go:build unix

package netopen

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const missingMcastIface = "no-such-iface-socat-test"

func TestListenUDPJoinsIPv6GroupFromJoinGroupOption(t *testing.T) {
	iface := multicastIfaceName(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if err != nil {
		t.Fatalf("ipv6-join-group on UDP6-RECV: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestListenUDPJoinsIPv4GroupFromIPAddMembership(t *testing.T) {
	iface := multicastIfaceName(t)
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-add-membership=224.0.0.1:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, spec)
	if err != nil {
		t.Fatalf("ip-add-membership on UDP4-RECV: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestListenUDPAppliesRepeatedMembershipInOrder(t *testing.T) {
	iface := multicastIfaceName(t)
	// First invalid, then valid: last-wins would succeed; apply-all must fail.
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + missingMcastIface + ",ipv6-join-group=[ff02::3]:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if c != nil {
		_ = c.Close()
	}
	if err == nil {
		t.Fatal("last-wins would ignore the invalid first membership option")
	}
	if !strings.Contains(err.Error(), missingMcastIface) {
		t.Fatalf("error=%v want %q", err, missingMcastIface)
	}

	spec, err = parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + iface + ",ipv6-join-group=[ff02::3]:" + iface)
	if err != nil {
		t.Fatal(err)
	}
	c, err = listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if err != nil {
		t.Fatalf("repeated valid ipv6-join-group: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestUDP6ConnectProcessesMembershipInterface(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := xio.OpenChannel(ctx, parseChannel(t, "UDP6:[::1]:9,ipv6-join-group=[ff02::2]:"+missingMcastIface), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("UDP6 connect with invalid membership interface succeeded (option was a no-op)")
	}
	if !strings.Contains(err.Error(), missingMcastIface) {
		t.Fatalf("error=%v want %q", err, missingMcastIface)
	}
}

func TestTCP6ConnectProcessesMembershipInterface(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := xio.OpenChannel(ctx, parseChannel(t, "TCP6:[::1]:1,ipv6-join-group=[ff02::2]:"+missingMcastIface+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("TCP6 connect with invalid membership interface succeeded (option was a no-op)")
	}
	if !strings.Contains(err.Error(), missingMcastIface) {
		t.Fatalf("error=%v want %q", err, missingMcastIface)
	}
}

func TestUDP6DatagramProcessesMembershipInterface(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := xio.OpenChannel(ctx, parseChannel(t, "UDP6-DATAGRAM:[::1]:9,ipv6-join-group=[ff02::2]:"+missingMcastIface), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("UDP6-DATAGRAM with invalid membership interface succeeded (option was a no-op)")
	}
	if !strings.Contains(err.Error(), missingMcastIface) {
		t.Fatalf("error=%v want %q", err, missingMcastIface)
	}
}

func TestListenUDPJoinsIPv4NumericIndex(t *testing.T) {
	ifi := multicastIface(t)
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-add-membership=224.0.0.1:" + strconv.Itoa(ifi.Index))
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, spec)
	if err != nil {
		t.Fatalf("ip-add-membership numeric index: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestListenUDPJoinsIPv6NumericIndex(t *testing.T) {
	ifi := multicastIface(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + strconv.Itoa(ifi.Index))
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, spec)
	if err != nil {
		t.Fatalf("ipv6-join-group numeric index: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestListenUDPJoinsIPv4ThreeFieldNameAndIndex(t *testing.T) {
	ifi := multicastIface(t)
	addr := firstIPv4(t, ifi)
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-add-membership=224.0.0.1:" + addr + ":" + ifi.Name)
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, spec)
	if err != nil {
		t.Fatalf("three-field name: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	spec, err = parse.ParseSpec("UDP4-RECV:0,ip-add-membership=224.0.0.1:" + addr + ":" + strconv.Itoa(ifi.Index))
	if err != nil {
		t.Fatal(err)
	}
	c, err = listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, spec)
	if err != nil {
		t.Fatalf("three-field index: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func multicastIface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 && ifi.Flags&net.FlagLoopback != 0 {
			return ifi
		}
	}
	t.Skip("no multicast loopback interface")
	return net.Interface{}
}

func firstIPv4(t *testing.T, ifi net.Interface) string {
	t.Helper()
	addrs, err := ifi.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipn.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	t.Skipf("%s has no IPv4 address", ifi.Name)
	return ""
}

func multicastIfaceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 && ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 {
			return ifi.Name
		}
	}
	t.Skip("no multicast interface")
	return ""
}
