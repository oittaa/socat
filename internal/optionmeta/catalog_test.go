package optionmeta

import "testing"

func TestCatalogRejectsDuplicates(t *testing.T) {
	for _, second := range []Def{
		{Canonical: "one", Help: HelpHidden},
		{Canonical: "two", Aliases: []string{"alias"}, Help: HelpHidden},
		{Canonical: "two", ParserAliases: []string{"one"}, Help: HelpHidden},
		{Canonical: "two", PublicAliases: []string{"alias"}, Help: HelpHidden},
	} {
		defs := []Def{{Canonical: "one", Aliases: []string{"alias"}, Help: HelpHidden}, second}
		if err := validateCatalog(defs); err == nil {
			t.Errorf("accepted colliding definition: %+v", second)
		}
	}
	def := Def{Canonical: "one", Aliases: []string{"alias"}, ParserAliases: []string{"alias"}, Help: HelpHidden}
	if err := validateCatalog([]Def{def}); err == nil {
		t.Fatal("accepted the same alias in two categories")
	}
}

func TestLookupReturnsIndependentDefinition(t *testing.T) {
	d, ok := Lookup("nodelay")
	if !ok {
		t.Fatal("missing nodelay")
	}
	alias, cap := d.Aliases[0], d.Apply.Caps[0]
	d.Aliases[0], d.Apply.Caps[0] = "changed", "changed"
	again, _ := Lookup("nodelay")
	if again.Aliases[0] != alias || again.Apply.Caps[0] != cap {
		t.Fatal("editing a lookup result changed the catalog")
	}
}
