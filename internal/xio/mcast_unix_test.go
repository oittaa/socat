//go:build linux || darwin

package xio

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

const missingMcastIface = "no-such-iface-socat-test"

func decodeMulticastJoin(t *testing.T, raw string) addrconfig.MulticastRequest {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	config := mustDecodeAddress(t, spec)
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionMulticast &&
			(action.Multicast.Kind == addrconfig.MulticastJoinIPv4 || action.Multicast.Kind == addrconfig.MulticastJoinIPv6) {
			return action.Multicast
		}
	}
	t.Fatal("no membership join")
	return addrconfig.MulticastRequest{}
}

func TestDecodeMcastSpecBracketIPv6(t *testing.T) {
	req := decodeMulticastJoin(t, "UDP6-RECV:1,ipv6-join-group=[ff02::2]:eth0")
	if req.Group.String() != "ff02::2" || req.InterfaceName != "eth0" || req.InterfaceIsID || req.ThreeField {
		t.Fatalf("parsed=%+v", req)
	}
}

func TestDecodeMcastSpecIPv4Address(t *testing.T) {
	req := decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.1.2.3:127.0.0.1")
	if req.Group.String() != "224.1.2.3" || req.InterfaceName != "127.0.0.1" || req.ThreeField {
		t.Fatalf("parsed=%+v", req)
	}
}

func TestDecodeMcastSpecThreeFieldIPv4(t *testing.T) {
	req := decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.0.0.1:127.0.0.1:lo")
	if req.Group.String() != "224.0.0.1" || req.InterfaceAddr.String() != "127.0.0.1" || req.InterfaceName != "lo" || !req.ThreeField {
		t.Fatalf("name form=%+v", req)
	}

	req = decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.0.0.1:127.0.0.1:1")
	if req.InterfaceAddr.String() != "127.0.0.1" || !req.InterfaceIsID || req.InterfaceID != 1 {
		t.Fatalf("index form=%+v", req)
	}
}

func TestDecodeMcastSpecStoresClassicAddressNames(t *testing.T) {
	req := decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.0.0.1:localhost")
	if req.Group.String() != "224.0.0.1" || req.InterfaceName != "localhost" {
		t.Fatalf("parsed=%+v", req)
	}
	if _, err := net.InterfaceByName("localhost"); err == nil {
		t.Skip("host has an interface literally named localhost")
	}
	addr, err := resolveMcastIPv4Address(addrconfig.HostFromText(req.InterfaceName))
	if err != nil || !addr.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("localhost=%v err=%v", addr, err)
	}
}

func TestIPAddMembershipRejectsIPv6Group(t *testing.T) {
	err := applyPreparedMulticast(0, decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=[ff02::2]:lo"))
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
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
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
	lc := net.ListenConfig{Control: ListenControl(mustDecodeAddress(t, spec))}
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
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if c != nil {
		_ = c.Close()
	}
	requireMissingMembershipIface(t, err)
}

func TestIPv4MembershipResolvesInterfaceAddressName(t *testing.T) {
	fd := mustUDP4Socket(t)
	if err := applyPreparedMulticast(fd, decodeMulticastJoin(t, "UDP:127.0.0.1:9,ip-add-membership=224.0.0.4:localhost")); err != nil {
		t.Fatalf("hostname interface address join: %v", err)
	}
}

func TestIPv4NumericIndexDoesNotRequireIPv4AddressOnIface(t *testing.T) {
	// Classic ip_mreqn keeps imr_ifindex; a missing IPv4 address on the
	// interface must not become "use 0.0.0.0 as if it were the ifindex".
	ifi := multicastLoopback(t)
	fd := mustUDP4Socket(t)
	raw := "UDP:127.0.0.1:9,ip-add-membership=224.0.0.1:" + strconv.Itoa(ifi.Index)
	if err := applyPreparedMulticast(fd, decodeMulticastJoin(t, raw)); err != nil {
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

func mustUDP4Socket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
