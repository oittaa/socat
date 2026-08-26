package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestMembershipJoinSpecReadsBothSpellings(t *testing.T) {
	join, err := parse.ParseSpec("UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	if got := membershipJoinSpec(join); got != "[ff02::2]:lo" {
		t.Fatalf("ipv6-join-group value=%q", got)
	}
	if join.HasOption("ip-add-membership") {
		t.Fatal("ipv6-join-group must not fold onto ip-add-membership")
	}

	member, err := parse.ParseSpec("UDP4-RECV:1,ip-add-membership=224.0.0.1:lo")
	if err != nil {
		t.Fatal(err)
	}
	if got := membershipJoinSpec(member); got != "224.0.0.1:lo" {
		t.Fatalf("ip-add-membership value=%q", got)
	}

	none, err := parse.ParseSpec("UDP4-RECV:1,reuseaddr")
	if err != nil {
		t.Fatal(err)
	}
	if got := membershipJoinSpec(none); got != "" {
		t.Fatalf("empty membership=%q", got)
	}
}

func TestMembershipJoinSpecLastWins(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,ip-add-membership=224.0.0.1:lo,ipv6-join-group=[ff02::2]:eth0")
	if err != nil {
		t.Fatal(err)
	}
	if got := membershipJoinSpec(s); got != "[ff02::2]:eth0" {
		t.Fatalf("last-wins value=%q", got)
	}
}
