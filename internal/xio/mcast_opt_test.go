package xio

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestMembershipJoinsReadsBothSpellings(t *testing.T) {
	join, err := parse.ParseSpec("UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	got := membershipJoins(join)
	if len(got) != 1 || got[0].family != membershipFamilyIPv6 || got[0].spec != "[ff02::2]:lo" {
		t.Fatalf("ipv6-join-group joins=%+v", got)
	}
	if join.HasOption("ip-add-membership") {
		t.Fatal("ipv6-join-group must not fold onto ip-add-membership")
	}

	member, err := parse.ParseSpec("UDP4-RECV:1,ip-add-membership=224.0.0.1:lo")
	if err != nil {
		t.Fatal(err)
	}
	got = membershipJoins(member)
	if len(got) != 1 || got[0].family != membershipFamilyIPv4 || got[0].spec != "224.0.0.1:lo" {
		t.Fatalf("ip-add-membership joins=%+v", got)
	}

	none, err := parse.ParseSpec("UDP4-RECV:1,reuseaddr")
	if err != nil {
		t.Fatal(err)
	}
	if got = membershipJoins(none); len(got) != 0 {
		t.Fatalf("empty membership=%+v", got)
	}
}

func TestMembershipJoinsCollectsAllInOptionOrder(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,ip-add-membership=224.0.0.1:lo,ipv6-join-group=[ff02::2]:eth0")
	if err != nil {
		t.Fatal(err)
	}
	got := membershipJoins(s)
	want := []membershipJoin{
		{family: membershipFamilyIPv4, spec: "224.0.0.1:lo", name: "ip-add-membership"},
		{family: membershipFamilyIPv6, spec: "[ff02::2]:eth0", name: "ipv6-join-group"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed joins=%+v want %+v", got, want)
	}
}

func TestMembershipJoinsCollectsRepeatedOptions(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo,ipv6-join-group=[ff02::3]:eth0")
	if err != nil {
		t.Fatal(err)
	}
	got := membershipJoins(s)
	if len(got) != 2 {
		t.Fatalf("repeated joins=%+v", got)
	}
	if got[0].spec != "[ff02::2]:lo" || got[1].spec != "[ff02::3]:eth0" {
		t.Fatalf("repeated order=%+v", got)
	}
	if got[0].family != membershipFamilyIPv6 || got[1].family != membershipFamilyIPv6 {
		t.Fatalf("repeated family=%+v", got)
	}
}

func TestMembershipJoinsRecognizesClassicAliases(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,join-group=[ff02::2]:lo,add-membership=224.0.0.1:lo,membership=224.0.0.2:eth0,ipv6-add-membership=[ff02::3]:eth1")
	if err != nil {
		t.Fatal(err)
	}
	got := membershipJoins(s)
	wantFam := []membershipFamily{membershipFamilyIPv6, membershipFamilyIPv4, membershipFamilyIPv4, membershipFamilyIPv6}
	wantSpec := []string{"[ff02::2]:lo", "224.0.0.1:lo", "224.0.0.2:eth0", "[ff02::3]:eth1"}
	if len(got) != 4 {
		t.Fatalf("alias joins=%+v", got)
	}
	for i := range wantFam {
		if got[i].family != wantFam[i] || got[i].spec != wantSpec[i] {
			t.Fatalf("alias[%d]=%+v want family=%v spec=%q", i, got[i], wantFam[i], wantSpec[i])
		}
	}
}

func TestMembershipFamilyIgnoresAddressWhenClassifying(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,ip-add-membership=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	got := membershipJoins(s)
	if len(got) != 1 || got[0].family != membershipFamilyIPv4 {
		t.Fatalf("ip-add-membership must stay IPv4 sockopt family, got %+v", got)
	}

	s, err = parse.ParseSpec("UDP6-RECV:1,ipv6-join-group=224.0.0.1:lo")
	if err != nil {
		t.Fatal(err)
	}
	got = membershipJoins(s)
	if len(got) != 1 || got[0].family != membershipFamilyIPv6 {
		t.Fatalf("ipv6-join-group must stay IPv6 sockopt family, got %+v", got)
	}
}
