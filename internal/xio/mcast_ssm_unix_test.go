//go:build linux || darwin || freebsd

package xio

import (
	"bytes"
	"context"
	"net"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestGroupSourceReqLayout(t *testing.T) {
	want := uintptr(groupSourceReqSize)
	if unsafe.Sizeof(groupSourceReq{}) != want {
		t.Fatalf("groupSourceReq size=%d want %d", unsafe.Sizeof(groupSourceReq{}), want)
	}
}

func TestListenControlAppliesIPv4SourceMembership(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-add-source-membership=232.1.1.1:127.0.0.1:10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	want := packIPMreqSource(net.IPv4(232, 1, 1, 1), net.IPv4(127, 0, 0, 1), net.IPv4(10, 0, 0, 1))
	var calls int
	restore := SetSockoptTestHook(func(call SockoptCall) {
		if call.AsInt || call.Opt != unix.IP_ADD_SOURCE_MEMBERSHIP {
			return
		}
		calls++
		if !bytes.Equal(call.Bytes, want[:]) {
			t.Errorf("IP_ADD_SOURCE_MEMBERSHIP payload=%v want %v", call.Bytes, want[:])
		}
	})
	t.Cleanup(restore)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if calls != 1 {
		t.Fatalf("IP_ADD_SOURCE_MEMBERSHIP setsockopt calls=%d want 1", calls)
	}
}

func TestIPv6SourceMembershipInterfaceRequired(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-source-group=[ff3e::1]:" + missingMcastIface + ":[::1]")
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

func TestListenControlAppliesIPv6SourceMembership(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	ifi := multicastCapableInterface(t)
	spec, err := parse.ParseSpec("UDP6-RECV:0,ipv6-join-source-group=[ff3e::1]:" + ifi.Name + ":[::1]")
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	restore := SetSockoptTestHook(func(call SockoptCall) {
		if !call.AsInt && call.Opt == unix.MCAST_JOIN_SOURCE_GROUP {
			calls++
		}
	})
	t.Cleanup(restore)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if calls != 1 {
		t.Fatalf("MCAST_JOIN_SOURCE_GROUP setsockopt calls=%d want 1", calls)
	}
}

func TestParseSourceMcastSpec(t *testing.T) {
	p, err := parseSourceMcastSpec("232.1.1.1:127.0.0.1:10.0.0.1", "ip-add-source-membership", membershipFamilyIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if p.group.String() != "232.1.1.1" || p.ifaceAddr.String() != "127.0.0.1" || p.source.String() != "10.0.0.1" {
		t.Fatalf("parsed=%+v", p)
	}
	p, err = parseSourceMcastSpec("[ff3e::1]:lo:[::1]", "ipv6-join-source-group", membershipFamilyIPv6)
	if err != nil {
		t.Fatal(err)
	}
	if p.group.String() != "ff3e::1" || p.token != "lo" || p.source.String() != "::1" {
		t.Fatalf("ipv6 parsed=%+v", p)
	}
	if _, err := parseSourceMcastSpec("232.1.1.1:127.0.0.1", "ip-add-source-membership", membershipFamilyIPv4); err == nil {
		t.Fatal("two-field SSM must fail")
	}
}
