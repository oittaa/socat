//go:build linux || darwin

package xio

import (
	"net"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
)

func TestGroupSourceReqLayout(t *testing.T) {
	want := uintptr(groupSourceReqSize)
	if unsafe.Sizeof(groupSourceReq{}) != want {
		t.Fatalf("groupSourceReq size=%d want %d", unsafe.Sizeof(groupSourceReq{}), want)
	}
}

func TestIPv6SourceMembershipInterfaceRequired(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-source-group=[ff3e::1]:" + missingMcastIface + ":[::1]")
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
