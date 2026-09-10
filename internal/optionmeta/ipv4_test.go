package optionmeta

import "testing"

func TestGetOnlyIPv4CopiesAliases(t *testing.T) {
	a := GetOnlyIPv4()
	a[0].Aliases[0] = "mutated"
	if GetOnlyIPv4()[0].Aliases[0] != "ipmtu" {
		t.Fatal("catalog alias slice was shared")
	}
}
