package parse

import "testing"

func TestGetOnlyIPv4AliasesFold(t *testing.T) {
	want := map[string]string{
		"ip-mtu": "ip-mtu", "ipmtu": "ip-mtu", "mtu": "ip-mtu",
		"ip-pktoptions": "ip-pktoptions", "ippktoptions": "ip-pktoptions",
		"pktoptions": "ip-pktoptions", "pktopts": "ip-pktoptions",
	}
	for spelling, canonical := range want {
		if got := CanonicalOptionName(spelling); got != canonical {
			t.Errorf("%s -> %s", spelling, got)
		}
	}
}

func TestGetOnlyIPv4ParseKeepsSpelling(t *testing.T) {
	s, err := ParseSpec("UDP4:127.0.0.1:1,MTU=1")
	if err != nil {
		t.Fatal(err)
	}
	o := s.Options[0]
	if o.Name != "ip-mtu" || o.Spelling != "mtu" || !o.Has || o.Value != "1" {
		t.Fatalf("%+v", o)
	}
	s = Spec{Options: []Option{{Name: "ipmtu"}}}
	if !s.HasOption("ip-mtu") {
		t.Fatal("constructed Name=ipmtu")
	}
	if CanonicalOptionName("ip-mtu-discover") != "ip-mtu-discover" {
		t.Fatal("ip-mtu-discover folded onto ip-mtu")
	}
}
