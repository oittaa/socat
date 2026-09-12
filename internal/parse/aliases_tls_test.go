package parse

import "testing"

func TestHiddenTLSAliasesFold(t *testing.T) {
	want := map[string]string{
		"openssl-method": "openssl-method", "opensslmethod": "openssl-method", "method": "openssl-method",
		"openssl-fips": "openssl-fips", "fips": "openssl-fips",
		"openssl-egd": "openssl-egd", "egd": "openssl-egd",
		"openssl-pseudo": "openssl-pseudo", "pseudo": "openssl-pseudo",
		"openssl-dhparam": "openssl-dhparam", "openssl-dhparams": "openssl-dhparam",
		"dhparam": "openssl-dhparam", "dhparams": "openssl-dhparam", "dh": "openssl-dhparam",
		"openssl-maxfraglen": "openssl-maxfraglen", "maxfraglen": "openssl-maxfraglen",
		"openssl-maxsendfrag": "openssl-maxsendfrag", "maxsendfrag": "openssl-maxsendfrag",
	}
	for spelling, canonical := range want {
		if got := CanonicalOptionName(spelling); got != canonical {
			t.Errorf("CanonicalOptionName(%q)=%q want %q", spelling, got, canonical)
		}
	}
}

func TestHiddenTLSParseKeepsSpelling(t *testing.T) {
	s, err := ParseSpec("OPENSSL:localhost:443,METHOD=SSL3")
	if err != nil {
		t.Fatal(err)
	}
	o := s.Options[0]
	if o.Name != "openssl-method" || o.Spelling != "method" || !o.Has || o.Value != "SSL3" {
		t.Fatalf("%+v", o)
	}
	s = Spec{Options: []Option{{Name: "fips"}}}
	if !hasOption(s, "openssl-fips") {
		t.Fatal("constructed Name=fips")
	}
	if CanonicalOptionName("fipss") != "fipss" {
		t.Fatal("typo folded")
	}
}

func TestEGDAndDHParamAreNotPathOptions(t *testing.T) {
	if pathOption("egd") || pathOption("dhparam") {
		t.Fatal("egd/dhparam must not use Windows path syntax")
	}
}
