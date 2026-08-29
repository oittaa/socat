package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestRejectUnsupportedGetOnlyIPv4(t *testing.T) {
	for _, spec := range []string{
		"UDP4:127.0.0.1:1,ip-mtu",
		"UDP4:127.0.0.1:1,mtu=1",
		"TCP:127.0.0.1:1,ipmtu",
		"UDP4:127.0.0.1:1,ip-pktoptions",
		"UDP:127.0.0.1:1,pktopts",
		"TCP4:127.0.0.1:1,pktoptions=1",
	} {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		err = RejectUnsupportedRemainingIPv4(s)
		if err == nil || !strings.Contains(err.Error(), "get-only") {
			t.Errorf("%s: err=%v want get-only", spec, err)
		}
	}
}

func TestGetOnlyIPv4DoesNotMatchMTUDiscover(t *testing.T) {
	s, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-mtu-discover=2")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRemainingIPv4(s); err != nil {
		t.Fatalf("ip-mtu-discover: %v", err)
	}
}

func TestRejectUnsupportedRouterAlert(t *testing.T) {
	tcp, err := parse.ParseSpec("TCP4:127.0.0.1:1,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedRemainingIPv4(tcp)
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("TCP ip-router-alert err=%v want address type", err)
	}

	udp, err := parse.ParseSpec("UDP4:127.0.0.1:1,routeralert")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedRemainingIPv4(udp)
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("UDP ip-router-alert err=%v want address type", err)
	}

	ip6, err := parse.ParseSpec("IP6-SENDTO:[::1]:1,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedRemainingIPv4(ip6)
	if err == nil || !strings.Contains(err.Error(), "not supported on IPv6") {
		t.Fatalf("IP6 ip-router-alert err=%v want IPv6", err)
	}

	raw, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:255,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedRemainingIPv4(raw)
	if err == nil || !strings.Contains(err.Error(), "IPPROTO_RAW") {
		t.Fatalf("IPPROTO_RAW ip-router-alert err=%v", err)
	}

	ok, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:1,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRemainingIPv4(ok); err != nil {
		t.Fatalf("ICMP raw ip-router-alert: %v", err)
	}
}

func TestGetOnlyIPv4OptionNamesCoverAliases(t *testing.T) {
	got := map[string]bool{}
	for _, name := range GetOnlyIPv4OptionNames() {
		got[name] = true
	}
	for _, name := range []string{"ip-mtu", "mtu", "ip-pktoptions", "pktopts"} {
		if !got[name] {
			t.Errorf("missing %q", name)
		}
	}
}
