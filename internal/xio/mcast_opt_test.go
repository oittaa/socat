package xio

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func membershipJoins(s parse.Spec) []membershipJoin {
	var out []membershipJoin
	for _, o := range s.Options {
		family, name, ok := membershipFamilyOf(o)
		if !ok {
			continue
		}
		out = append(out, membershipJoin{family: family, spec: o.Value, name: name})
	}
	return out
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

func TestMTUDiscoveryAliases(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family membershipFamily
	}{
		{name: "ip-mtu-discover", family: membershipFamilyIPv4},
		{name: "mtudiscover", family: membershipFamilyIPv4},
		{name: "ipmtudiscover", family: membershipFamilyIPv4},
		{name: "ipv6-mtu-discover", family: membershipFamilyIPv6},
		{name: "mtudiscover6", family: membershipFamilyIPv6},
	} {
		family, _, ok := mtuDiscoveryName(tc.name)
		if !ok || family != tc.family {
			t.Errorf("mtuDiscoveryName(%q)=(%v,%v), want family %v", tc.name, family, ok, tc.family)
		}
	}
}
