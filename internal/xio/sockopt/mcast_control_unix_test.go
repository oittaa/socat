//go:build linux || darwin

package sockopt_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const missingMcastIface = "no-such-iface-socat-test"

func TestDialControlUDP6RejectsInvalidMembershipInterface(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-group=[ff02::2]:" + missingMcastIface)
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: xio.DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
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
	lc := net.ListenConfig{Control: xio.ListenControl(mustDecodeAddress(t, spec))}
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
	d := &net.Dialer{Control: xio.DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
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
