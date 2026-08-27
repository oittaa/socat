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

func TestMembershipFamilyPrefersOriginalSpelling(t *testing.T) {
	o := parse.Option{
		Name:     "ip-add-membership",
		Spelling: "ipv6-join-group",
		Value:    "[ff02::2]:lo",
		Has:      true,
	}
	family, name, ok := membershipFamilyOf(o)
	if !ok || family != membershipFamilyIPv6 || name != "ipv6-join-group" {
		t.Fatalf("family=%v name=%q ok=%v", family, name, ok)
	}
}

func TestSourceMembershipFamilyStaysDistinct(t *testing.T) {
	s, err := parse.ParseSpec("UDP6-RECV:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]")
	if err != nil {
		t.Fatal(err)
	}
	if s.HasOption("ip-add-source-membership") {
		t.Fatal("ipv6-join-source-group must not fold onto ip-add-source-membership")
	}
	family, name, ok := sourceMembershipOf(s.Options[0])
	if !ok || family != membershipFamilyIPv6 || name != "ipv6-join-source-group" {
		t.Fatalf("family=%v name=%q ok=%v", family, name, ok)
	}

	s, err = parse.ParseSpec("UDP4-RECV:1,source-membership=232.1.1.1:127.0.0.1:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	family, name, ok = sourceMembershipOf(s.Options[0])
	if !ok || family != membershipFamilyIPv4 || name != "ip-add-source-membership" {
		t.Fatalf("alias family=%v name=%q ok=%v", family, name, ok)
	}
}

func TestMulticastNamedAliases(t *testing.T) {
	s, err := parse.ParseSpec("UDP4:localhost:1,mcloop=0,multicast-ttl=9,multicast-if=127.0.0.1,mcloop6=1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range s.Options {
		kind, name, ok := multicastNamedOf(o)
		if !ok {
			t.Fatalf("unrecognized %+v", o)
		}
		got[name] = o.Value
		if name == "ipv6-multicast-loop" && kind != multicastNamedIPv6Loop {
			t.Fatalf("mcloop6 kind=%v", kind)
		}
	}
	if got["ip-multicast-loop"] != "0" || got["ip-multicast-ttl"] != "9" || got["ip-multicast-if"] != "127.0.0.1" || got["ipv6-multicast-loop"] != "1" {
		t.Fatalf("got=%v", got)
	}
}

func TestClassicFlagInt(t *testing.T) {
	n, err := classicFlagInt(parse.Option{}, 255)
	if err != nil || n != 1 {
		t.Fatalf("bare flag: n=%d err=%v want 1", n, err)
	}
	n, err = classicFlagInt(parse.Option{Has: true, Value: "false"}, 255)
	if err != nil || n != 0 {
		t.Fatalf("false: n=%d err=%v", n, err)
	}
	n, err = classicFlagInt(parse.Option{Has: true, Value: "9"}, 255)
	if err != nil || n != 9 {
		t.Fatalf("9: n=%d err=%v", n, err)
	}
	if _, err := classicFlagInt(parse.Option{Has: true, Value: "256"}, 255); err == nil {
		t.Fatal("TYPE_BYTE 256 must be rejected")
	}
	n, err = classicFlagInt(parse.Option{Has: true, Value: "2"}, -1)
	if err != nil || n != 2 {
		t.Fatalf("TYPE_INT 2: n=%d err=%v", n, err)
	}
}
