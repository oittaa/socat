//go:build linux || darwin

package xio

import (
	"net"
	"strings"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/addrconfig"
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

func decodeSourceMulticast(t *testing.T, raw string) addrconfig.SourceMulticastRequest {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	config := mustDecodeAddress(t, spec)
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionSourceMulticast {
			return action.Source
		}
	}
	t.Fatal("no source membership")
	return addrconfig.SourceMulticastRequest{}
}

func TestDecodeSourceMcastGroupIfaceSource(t *testing.T) {
	req := decodeSourceMulticast(t, "UDP:127.0.0.1:9,ip-add-source-membership=232.1.1.1:127.0.0.1:10.0.0.1")
	if req.Group.String() != "232.1.1.1" || req.Interface.String() != "127.0.0.1" || req.Source.String() != "10.0.0.1" {
		t.Fatalf("parsed=%+v", req)
	}
	req = decodeSourceMulticast(t, "UDP6:[::1]:9,ipv6-join-source-group=[ff3e::1]:lo:[::1]")
	if req.Group.String() != "ff3e::1" || req.Interface.String() != "lo" || req.Source.String() != "::1" {
		t.Fatalf("ipv6 parsed=%+v", req)
	}
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,ip-add-source-membership=232.1.1.1:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAddress(spec); err == nil {
		t.Fatal("two-field SSM must fail")
	} else if !strings.Contains(err.Error(), "group:iface:source") {
		t.Fatalf("two-field error=%v want group:iface:source", err)
	}
}
