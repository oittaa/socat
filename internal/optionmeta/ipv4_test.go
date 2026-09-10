package optionmeta

import "testing"

func TestGetOnlyIPv4Families(t *testing.T) {
	opts := GetOnlyIPv4()
	if len(opts) != 2 || opts[0].Canonical != "ip-mtu" || opts[0].Kernel != "IP_MTU" {
		t.Fatalf("%+v", opts)
	}
	if got := opts[1].Aliases; len(got) != 3 || got[0] != "ippktoptions" {
		t.Fatalf("%v", got)
	}
}

func TestGetOnlyIPv4CopiesAliases(t *testing.T) {
	a := GetOnlyIPv4()
	a[0].Aliases[0] = "mutated"
	if GetOnlyIPv4()[0].Aliases[0] != "ipmtu" {
		t.Fatal("catalog alias slice was shared")
	}
}

func TestValidateGetOnlyIPv4(t *testing.T) {
	opts := GetOnlyIPv4()
	opts[0].Canonical = ""
	if err := validateGetOnlyIPv4(opts); err == nil {
		t.Fatal("empty canonical")
	}
	opts = GetOnlyIPv4()
	opts[0].Kernel = ""
	if err := validateGetOnlyIPv4(opts); err == nil {
		t.Fatal("empty kernel")
	}
}
