//go:build unix

package xio

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

const missingMcastIface = "no-such-iface-socat-test"

func TestParseMcastSpecBracketIPv6(t *testing.T) {
	g, iface, err := parseMcastSpec("[ff02::2]:eth0", "ipv6-join-group")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "ff02::2" || iface != "eth0" {
		t.Fatalf("group=%s iface=%q", g, iface)
	}
}

func TestParseMcastSpecIPv4(t *testing.T) {
	g, iface, err := parseMcastSpec("224.1.2.3:127.0.0.1", "ip-add-membership")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "224.1.2.3" || iface != "127.0.0.1" {
		t.Fatalf("group=%s iface=%q", g, iface)
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
