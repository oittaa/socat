//go:build unix

package xio

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

const missingMcastIface = "no-such-iface-socat-test"

func TestParseMcastSpecBracketIPv6(t *testing.T) {
	p, err := parseMcastSpec("[ff02::2]:eth0", "ipv6-join-group")
	if err != nil {
		t.Fatal(err)
	}
	if p.group.String() != "ff02::2" || p.token != "eth0" || p.ifaceAddr != nil {
		t.Fatalf("parsed=%+v", p)
	}
}

func TestParseMcastSpecIPv4Address(t *testing.T) {
	p, err := parseMcastSpec("224.1.2.3:127.0.0.1", "ip-add-membership")
	if err != nil {
		t.Fatal(err)
	}
	if p.group.String() != "224.1.2.3" || p.token != "" || p.ifaceAddr.String() != "127.0.0.1" {
		t.Fatalf("parsed=%+v", p)
	}
}

func TestParseMcastSpecNumericIndex(t *testing.T) {
	p, err := parseMcastSpec("224.0.0.1:1", "ip-add-membership")
	if err != nil {
		t.Fatal(err)
	}
	if p.token != "1" || p.ifaceAddr != nil {
		t.Fatalf("parsed=%+v want token index 1", p)
	}
	idx, set, err := resolveMcastInterface(p, "ip-add-membership")
	if err != nil || !set || idx != 1 {
		t.Fatalf("index=%d set=%v err=%v", idx, set, err)
	}

	p, err = parseMcastSpec("[ff02::1]:1", "ipv6-join-group")
	if err != nil {
		t.Fatal(err)
	}
	idx, set, err = resolveMcastInterface(p, "ipv6-join-group")
	if err != nil || !set || idx != 1 {
		t.Fatalf("ipv6 index=%d set=%v err=%v", idx, set, err)
	}
}

func TestParseMcastSpecThreeFieldIPv4(t *testing.T) {
	p, err := parseMcastSpec("224.0.0.1:127.0.0.1:lo", "ip-add-membership")
	if err != nil {
		t.Fatal(err)
	}
	if p.group.String() != "224.0.0.1" || p.ifaceAddr.String() != "127.0.0.1" || p.token != "lo" {
		t.Fatalf("name form=%+v", p)
	}

	p, err = parseMcastSpec("224.0.0.1:127.0.0.1:1", "ip-add-membership")
	if err != nil {
		t.Fatal(err)
	}
	if p.ifaceAddr.String() != "127.0.0.1" || p.token != "1" {
		t.Fatalf("index form=%+v", p)
	}
}

func TestParseDecimalIndexDoesNotUseInterfaceByName(t *testing.T) {
	if _, ok := parseDecimalIndex("1"); !ok {
		t.Fatal("1 should be a numeric index")
	}
	if _, ok := parseDecimalIndex("lo"); ok {
		t.Fatal("lo is a name, not an index")
	}
	if _, ok := parseDecimalIndex("127.0.0.1"); ok {
		t.Fatal("IPv4 address is not an index")
	}
}

func TestIPAddMembershipRejectsIPv6Group(t *testing.T) {
	err := joinMulticastFD(0, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   "[ff02::2]:lo",
		name:   "ip-add-membership",
	})
	if err == nil || !strings.Contains(err.Error(), "IPv4 membership") {
		t.Fatalf("error=%v want IPv4 membership group mismatch", err)
	}
}

func TestDialControlUDP6RejectsInvalidMembershipInterface(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-group=[ff02::2]:" + missingMcastIface)
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if c != nil {
		_ = c.Close()
	}
	requireMissingMembershipIface(t, err)
}

func TestListenControlTCP6RejectsInvalidMembershipInterface(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("TCP6-LISTEN:0,ipv6-join-group=[ff02::2]:" + missingMcastIface)
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	ln, err := lc.Listen(context.Background(), "tcp6", "[::1]:0")
	if ln != nil {
		_ = ln.Close()
	}
	requireMissingMembershipIface(t, err)
}

func TestApplyMembershipJoinsAppliesAllInOrder(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-group=[ff02::2]:" + missingMcastIface + ",ipv6-join-group=[ff02::3]:lo")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if c != nil {
		_ = c.Close()
	}
	requireMissingMembershipIface(t, err)
}

func TestIPv4MembershipInterfaceNameAndIndex(t *testing.T) {
	ifi := multicastLoopback(t)
	fd := mustUDP4Socket(t)

	if err := joinMulticastFD(fd, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   "224.0.0.1:" + ifi.Name,
		name:   "ip-add-membership",
	}); err != nil {
		t.Fatalf("name join: %v", err)
	}

	fd2 := mustUDP4Socket(t)
	if err := joinMulticastFD(fd2, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   "224.0.0.2:" + strconv.Itoa(ifi.Index),
		name:   "ip-add-membership",
	}); err != nil {
		t.Fatalf("index join: %v", err)
	}
}

func TestIPv6MembershipInterfaceNameAndIndex(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	ifi := multicastLoopback(t)
	fd := mustUDP6Socket(t)
	if err := joinMulticastFD(fd, membershipJoin{
		family: membershipFamilyIPv6,
		spec:   "[ff02::2]:" + ifi.Name,
		name:   "ipv6-join-group",
	}); err != nil {
		t.Fatalf("name join: %v", err)
	}

	fd2 := mustUDP6Socket(t)
	if err := joinMulticastFD(fd2, membershipJoin{
		family: membershipFamilyIPv6,
		spec:   "[ff02::3]:" + strconv.Itoa(ifi.Index),
		name:   "ipv6-join-group",
	}); err != nil {
		t.Fatalf("index join: %v", err)
	}
}

func TestIPv4ThreeFieldMembershipNameAndIndex(t *testing.T) {
	ifi := multicastLoopback(t)
	addr := firstIPv4(t, ifi)
	fd := mustUDP4Socket(t)
	spec := "224.0.0.1:" + addr + ":" + ifi.Name
	if err := joinMulticastFD(fd, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   spec,
		name:   "ip-add-membership",
	}); err != nil {
		t.Fatalf("three-field name %s: %v", spec, err)
	}

	fd2 := mustUDP4Socket(t)
	spec = "224.0.0.1:" + addr + ":" + strconv.Itoa(ifi.Index)
	if err := joinMulticastFD(fd2, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   spec,
		name:   "ip-add-membership",
	}); err != nil {
		t.Fatalf("three-field index %s: %v", spec, err)
	}
}

func TestIPv4NumericIndexDoesNotRequireIPv4AddressOnIface(t *testing.T) {
	// Classic ip_mreqn keeps imr_ifindex; a missing IPv4 address on the
	// interface must not become "use 0.0.0.0 as if it were the ifindex".
	ifi := multicastLoopback(t)
	fd := mustUDP4Socket(t)
	if err := joinMulticastFD(fd, membershipJoin{
		family: membershipFamilyIPv4,
		spec:   "224.0.0.1:" + strconv.Itoa(ifi.Index),
		name:   "ip-add-membership",
	}); err != nil {
		t.Fatalf("index-only join: %v", err)
	}
}

func requireMissingMembershipIface(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected membership/interface error, option was a silent no-op")
	}
	if !strings.Contains(err.Error(), missingMcastIface) {
		t.Fatalf("error=%v want %q", err, missingMcastIface)
	}
}

func skipWithoutIPv6Loopback(t *testing.T) {
	t.Helper()
	c, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	_ = c.Close()
}

func multicastLoopback(t *testing.T) net.Interface {
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
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	t.Skipf("%s has no IPv4 address", ifi.Name)
	return ""
}

func mustUDP4Socket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func mustUDP6Socket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
