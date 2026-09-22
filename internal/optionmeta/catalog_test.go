package optionmeta

import (
	"strings"
	"testing"
)

func TestCatalogRejectsDuplicates(t *testing.T) {
	for _, second := range []Option{
		{Canonical: "one", Hidden: true},
		{Canonical: "two", Aliases: []string{"alias"}, Hidden: true},
		{Canonical: "two", ParserAliases: []string{"one"}, Hidden: true},
		{Canonical: "two", PublicAliases: []string{"alias"}, Hidden: true},
	} {
		defs := []Option{{Canonical: "one", Aliases: []string{"alias"}, Hidden: true}, second}
		if err := validateCatalog(defs); err == nil {
			t.Errorf("accepted colliding definition: %+v", second)
		}
	}
	def := Option{Canonical: "one", Aliases: []string{"alias"}, ParserAliases: []string{"alias"}, Hidden: true}
	if err := validateCatalog([]Option{def}); err == nil {
		t.Fatal("accepted the same alias in two categories")
	}
}

func TestProtocolFamilyHelpListsWorkingValues(t *testing.T) {
	d, ok := Lookup("pf")
	if !ok {
		t.Fatal("missing pf")
	}
	if strings.Contains(d.Desc, "4, 6") {
		t.Fatalf("help advertises numeric 4 and 6: %s", d.Desc)
	}
	for _, word := range []string{"ip4", "ipv4", "inet", "ip6", "ipv6", "inet6"} {
		if !strings.Contains(d.Desc, word) {
			t.Fatalf("help %q missing %s", d.Desc, word)
		}
	}
}

func TestLinuxOnlyTermiosAreCatalogued(t *testing.T) {
	for _, name := range []string{"iuclc", "olcuc", "xcase", "xtabs", "tabdly", "vswtc"} {
		d, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s is not in the catalog", name)
		}
		if d.Advertise != AdvertiseLinux {
			t.Fatalf("%s advertise=%v want Linux", name, d.Advertise)
		}
		if d.Visible() {
			t.Fatalf("%s must stay out of help", name)
		}
	}
}

func TestLookupReturnsIndependentDefinition(t *testing.T) {
	d, ok := Lookup("nodelay")
	if !ok {
		t.Fatal("missing nodelay")
	}
	alias, cap := d.Aliases[0], d.Scope.Caps[0]
	d.Aliases[0], d.Scope.Caps[0] = "changed", "changed"
	again, _ := Lookup("nodelay")
	if again.Aliases[0] != alias || again.Scope.Caps[0] != cap {
		t.Fatal("editing a lookup result changed the catalog")
	}
}
