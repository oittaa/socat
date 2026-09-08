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
