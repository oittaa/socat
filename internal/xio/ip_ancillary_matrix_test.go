package xio

import (
	"reflect"
	"runtime"
	"strings"
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
		{GroupRawIP, "ip-hdrincl", true},
		{GroupRawIP, "hdrincl", true},
		{GroupRawIP, "iphdrincl", true},
		{GroupTCP, "ip-hdrincl", false},
		{GroupUDP, "ip-hdrincl", false},
		{GroupQUIC, "ip-hdrincl", false},
		{GroupTCP, "ip-ttl", true},
		{GroupTCP, "ip-tos", true},
		{GroupTCP, "ipv6-tclass", true},
		{GroupTCP, "ip-pktinfo", false},
		{GroupUDP, "ip-recvdstaddr", true},
		{GroupUDP, "recvdstaddr", true},
		{GroupUDP, "ip-recvif", true},
		{GroupRawIP, "ip-recvif", true},
		{GroupTCP, "ip-recvdstaddr", false},
		{GroupTCP, "ip-recvif", false},
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
		{GroupUDP, "ip-retopts", true},
		{GroupRawIP, "ip-retopts", true},
		{GroupTCP, "ip-retopts", false},
		{GroupQUIC, "ip-retopts", false},
		{GroupUDP, "ipv6-recvdstopts", true},
		{GroupUDP, "recvdstopts", true},
		{GroupRawIP, "ipv6-recvhopopts", true},
		{GroupRawIP, "recvhopopts", true},
		{GroupUDP, "ipv6-recvrthdr", true},
		{GroupUDP, "recvrthdr", true},
		{GroupUDP, "ipv6-recvpathmtu", true},
		{GroupRawIP, "ipv6-recvpathmtu", true},
		{GroupTCP, "ipv6-recvdstopts", false},
		{GroupQUIC, "ipv6-recvhopopts", false},
		{GroupTCP, "ipv6-recvrthdr", false},
		{GroupQUIC, "ipv6-recvpathmtu", false},
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
	hdrincl := IPAncillaryImplementationGroups("ip-hdrincl")
	if !reflect.DeepEqual(hdrincl, []string{GroupRawIP}) {
		t.Fatalf("ip-hdrincl groups=%v want [%s]", hdrincl, GroupRawIP)
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("hdrincl"), hdrincl) {
		t.Fatalf("hdrincl groups=%v want %v", IPAncillaryImplementationGroups("hdrincl"), hdrincl)
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("iphdrincl"), hdrincl) {
		t.Fatalf("iphdrincl groups=%v want %v", IPAncillaryImplementationGroups("iphdrincl"), hdrincl)
	}
	retopts := IPAncillaryImplementationGroups("ip-retopts")
	if !reflect.DeepEqual(retopts, ipAncillaryRecvGroups) {
		t.Fatalf("ip-retopts groups=%v want recv groups %v", retopts, ipAncillaryRecvGroups)
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("retopts"), retopts) {
		t.Fatalf("retopts groups=%v want %v", IPAncillaryImplementationGroups("retopts"), retopts)
	}
	dstopts := IPAncillaryImplementationGroups("ipv6-recvdstopts")
	if !reflect.DeepEqual(dstopts, ipAncillaryRecvGroups) {
		t.Fatalf("ipv6-recvdstopts groups=%v want recv groups %v", dstopts, ipAncillaryRecvGroups)
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("recvdstopts"), dstopts) {
		t.Fatalf("recvdstopts groups=%v want %v", IPAncillaryImplementationGroups("recvdstopts"), dstopts)
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("ipv6-recvpathmtu"), dstopts) {
		t.Fatalf("ipv6-recvpathmtu groups=%v want %v", IPAncillaryImplementationGroups("ipv6-recvpathmtu"), dstopts)
	}
	if IPAncillaryImplementationGroups("recvpathmtu") != nil {
		t.Fatal("recvpathmtu must not be a matrix alias")
	}
	if IPAncillaryImplementationGroups("nodelay") != nil {
		t.Fatal("non-matrix option must not grow implementationGroups")
	}
	if !reflect.DeepEqual(IPAncillaryImplementationGroups("ippktinfo"), pktinfo) {
		t.Fatalf("ippktinfo groups=%v want %v", IPAncillaryImplementationGroups("ippktinfo"), pktinfo)
	}
	if len(pktinfo) == 0 {
		t.Fatal("empty implementationGroups means unrestricted; recv must keep UDP/raw IP groups on every platform")
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

func TestRejectUnsupportedIPAncillaryFamilyAndPlatform(t *testing.T) {
	cases := []struct {
		spec        string
		wantUnix    string
		wantWindows string
	}{
		{spec: "TCP4:127.0.0.1:1,ipv6-tclass=16", wantUnix: "not supported on IPv4", wantWindows: "not supported on this platform"},
		{spec: "TCP4:127.0.0.1:1,ipv6-unicast-hops=9", wantUnix: "not supported on IPv4", wantWindows: "not supported on this platform"},
		{spec: "UDP6:[::1]:1,ip-pktinfo", wantUnix: "not supported on IPv6", wantWindows: "not supported on this platform"},
		{spec: "UDP4:127.0.0.1:1,ipv6-recvpktinfo", wantUnix: "not supported on IPv4", wantWindows: "not supported on this platform"},
		{spec: "TCP6:[::1]:1,ip-ttl=9"},
		{spec: "TCP6:[::1]:1,ip-tos=16"},
		{spec: "TCP6:[::1]:1,ipv6-tclass=16", wantWindows: "not supported on this platform"},
		{spec: "UDP4:127.0.0.1:1,ip-pktinfo", wantWindows: "not supported on this platform"},
		{spec: "UDP4:127.0.0.1:1,ippktinfo", wantWindows: "not supported on this platform"},
		{spec: "TCP:127.0.0.1:1,ip-options=x01000000", wantWindows: "not supported on this platform"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = RejectUnsupportedIPAncillary(spec)
			want := tc.wantUnix
			if runtime.GOOS == "windows" {
				want = tc.wantWindows
			}
			if want == "" {
				if err != nil {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err=%v want substring %q", err, want)
			}
		})
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

func TestAncillaryRecvIntAliasLastWins(t *testing.T) {
	off, err := parse.ParseSpec("UDP:127.0.0.1:1,ip-recvttl=1,recvttl=0")
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err := ancillaryRecvInt(off, "ip-recvttl")
	if err != nil || !ok || n != 0 {
		t.Fatalf("ip-recvttl=1,recvttl=0 n=%d ok=%v err=%v want 0", n, ok, err)
	}
	if NeedAncillary(off) {
		t.Fatal("recvttl=0 must win and disable ReadMsg")
	}
	on, err := parse.ParseSpec("UDP:127.0.0.1:1,recvttl=0,iprecvttl=1")
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err = ancillaryRecvInt(on, "ip-recvttl")
	if err != nil || !ok || n != 1 {
		t.Fatalf("recvttl=0,iprecvttl=1 n=%d ok=%v err=%v want 1", n, ok, err)
	}
}

func TestRejectUnsupportedIPRecvdstaddrRecvif(t *testing.T) {
	udp, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recvdstaddr")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(udp)
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("darwin UDP ip-recvdstaddr: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}

	tcp, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-recvif")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(tcp)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("TCP ip-recvif err=%v want not supported", err)
	}
}

func TestRejectUnsupportedIPRetopts(t *testing.T) {
	udp, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-retopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(udp)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("linux UDP ip-retopts: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}

	udp6, err := parse.ParseSpec("UDP6:[::1]:1,ip-retopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(udp6)
	want := "not supported on IPv6"
	if runtime.GOOS != "linux" {
		want = "not supported on this platform"
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("UDP6 ip-retopts err=%v want %q", err, want)
	}

	tcp, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-retopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(tcp)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("TCP ip-retopts err=%v want not supported", err)
	}
}

func TestRejectUnsupportedIPv6RecvExt(t *testing.T) {
	udp6, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvdstopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(udp6)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("linux UDP6 ipv6-recvdstopts: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}

	raw, err := parse.ParseSpec("IP6-RECV:58,ipv6-recvpathmtu")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(raw)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("linux IP6-RECV ipv6-recvpathmtu: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}

	udp4, err := parse.ParseSpec("UDP4:127.0.0.1:1,ipv6-recvdstopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(udp4)
	want := "not supported on IPv4"
	if runtime.GOOS != "linux" {
		want = "not supported on this platform"
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("UDP4 ipv6-recvdstopts err=%v want %q", err, want)
	}

	tcp, err := parse.ParseSpec("TCP6:[::1]:1,ipv6-recvhopopts")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(tcp)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("TCP ipv6-recvhopopts err=%v want not supported", err)
	}

	quic, err := parse.ParseSpec("QUIC:[::1]:1,ipv6-recvrthdr")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedIPAncillary(quic)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("QUIC ipv6-recvrthdr err=%v want not supported", err)
	}
}
