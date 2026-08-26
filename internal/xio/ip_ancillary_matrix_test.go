package xio

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestIPAncillarySupportedMatrix(t *testing.T) {
	cases := []struct {
		group, option string
		want          bool
	}{
		{GroupUDP, "ip-pktinfo", true},
		{GroupUDP, "pktinfo", true},
		{GroupUDP, "so-timestamp", true},
		{GroupUDP, "ip-ttl", true},
		{GroupRawIP, "ip-recvttl", true},
		{GroupRawIP, "ip-options", true},
		{GroupTCP, "ip-ttl", true},
		{GroupTCP, "ip-tos", true},
		{GroupTCP, "ipv6-tclass", true},
		{GroupTCP, "ip-pktinfo", false},
		{GroupTCP, "so-timestamp", false},
		{GroupTCP, "ip-recvttl", false},
		{GroupQUIC, "ip-ttl", true},
		{GroupQUIC, "ipv6-unicast-hops", true},
		{GroupQUIC, "ip-pktinfo", false},
		{GroupQUIC, "so-timestamp", false},
		{GroupTLS, "ip-ttl", true},
		{GroupTLS, "ip-pktinfo", false},
		{GroupWebSocket, "ip-tos", true},
		{GroupProxy, "ip-ttl", true},
		{GroupSCTP, "ip-ttl", true},
		{GroupSCTP, "ip-recvopts", false},
		{GroupUnix, "so-timestamp", false},
		{GroupUnix, "ip-ttl", false},
		{GroupVSOCK, "ip-pktinfo", false},
		{GroupFiles, "ip-pktinfo", false},
		{GroupSocket, "so-timestamp", false},
		{GroupTUN, "ip-recvttl", false},
		// Options outside the matrix stay unrestricted here.
		{GroupTCP, "nodelay", true},
		{GroupFiles, "append", true},
	}
	for _, tc := range cases {
		got := IPAncillarySupported(tc.group, tc.option)
		if got != tc.want {
			t.Errorf("IPAncillarySupported(%q, %q)=%v want %v", tc.group, tc.option, got, tc.want)
		}
	}
}

func TestIPAncillaryImplementationGroupsAliases(t *testing.T) {
	pktinfo := IPAncillaryImplementationGroups("ip-pktinfo")
	if !reflect.DeepEqual(pktinfo, IPAncillaryImplementationGroups("pktinfo")) {
		t.Fatalf("pktinfo groups=%v ip-pktinfo=%v", IPAncillaryImplementationGroups("pktinfo"), pktinfo)
	}
	if !reflect.DeepEqual(pktinfo, ipAncillaryRecvGroups) {
		t.Fatalf("ip-pktinfo groups=%v want recv groups %v", pktinfo, ipAncillaryRecvGroups)
	}
	ttl := IPAncillaryImplementationGroups("ipttl")
	if !reflect.DeepEqual(ttl, ipAncillarySendGroups) {
		t.Fatalf("ipttl groups=%v want send groups %v", ttl, ipAncillarySendGroups)
	}
	if IPAncillaryImplementationGroups("nodelay") != nil {
		t.Fatal("non-matrix option must not grow implementationGroups")
	}
}

func TestRejectUnsupportedIPAncillaryWithoutRegistration(t *testing.T) {
	spec, err := parse.ParseSpec("NOTAREAL:host,ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedIPAncillary(spec); err != nil {
		t.Fatalf("unregistered type: %v", err)
	}
}

func TestAncillaryRecvIntPresenceAndZero(t *testing.T) {
	present, err := parse.ParseSpec("UDP:127.0.0.1:1,pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err := ancillaryRecvInt(present, "ip-pktinfo", "pktinfo")
	if err != nil || !ok || n != 1 {
		t.Fatalf("presence n=%d ok=%v err=%v want 1", n, ok, err)
	}
	off, err := parse.ParseSpec("UDP:127.0.0.1:1,pktinfo=0")
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err = ancillaryRecvInt(off, "ip-pktinfo", "pktinfo")
	if err != nil || !ok || n != 0 {
		t.Fatalf("pktinfo=0 n=%d ok=%v err=%v want 0", n, ok, err)
	}
	on, err := parse.ParseSpec("UDP:127.0.0.1:1,ip-pktinfo=1")
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err = ancillaryRecvInt(on, "ip-pktinfo", "pktinfo")
	if err != nil || !ok || n != 1 {
		t.Fatalf("ip-pktinfo=1 n=%d ok=%v err=%v want 1", n, ok, err)
	}
}
