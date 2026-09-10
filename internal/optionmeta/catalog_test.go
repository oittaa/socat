package optionmeta

import "testing"

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
