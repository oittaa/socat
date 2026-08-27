//go:build windows

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyMembershipJoinsUnsupportedOnWindows(t *testing.T) {
	none, err := parse.ParseSpec("UDP6:[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMembershipJoins(0, none); err != nil {
		t.Fatalf("no membership options: %v", err)
	}

	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-group=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyMembershipJoins(0, spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v want explicit Windows unsupported error", err)
	}

	for _, raw := range []string{
		"UDP4:127.0.0.1:9,ip-multicast-ttl=9",
		"UDP4:127.0.0.1:9,ip-add-source-membership=232.1.1.1:127.0.0.1:127.0.0.1",
		"TCP4-LISTEN:1,ip-freebind",
		"TCP4-LISTEN:1,ip-transparent",
		"UDP4:127.0.0.1:9,ip-mtu-discover=2",
		"UDP6:[::1]:9,ipv6-mtu-discover=2",
	} {
		spec, err = parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		err = ApplyPastSocketThenPrebind(0, spec, "udp4")
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: error=%v want not supported", raw, err)
		}
	}
}
