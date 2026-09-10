package parse

import "testing"

func TestUnsupportedTLSAliasMappings(t *testing.T) {
	want := map[string]string{
		"openssl-method":      "openssl-method",
		"opensslmethod":       "openssl-method",
		"method":              "openssl-method",
		"openssl-fips":        "openssl-fips",
		"fips":                "openssl-fips",
		"openssl-egd":         "openssl-egd",
		"egd":                 "openssl-egd",
		"openssl-pseudo":      "openssl-pseudo",
		"pseudo":              "openssl-pseudo",
		"openssl-dhparam":     "openssl-dhparam",
		"openssl-dhparams":    "openssl-dhparam",
		"dhparam":             "openssl-dhparam",
		"dhparams":            "openssl-dhparam",
		"dh":                  "openssl-dhparam",
		"openssl-maxfraglen":  "openssl-maxfraglen",
		"maxfraglen":          "openssl-maxfraglen",
		"openssl-maxsendfrag": "openssl-maxsendfrag",
		"maxsendfrag":         "openssl-maxsendfrag",
	}
	if len(want) != 18 {
		t.Fatalf("spelling count=%d want 18", len(want))
	}
	for spelling, canonical := range want {
		if got := CanonicalOptionName(spelling); got != canonical {
			t.Errorf("CanonicalOptionName(%q)=%q want %q", spelling, got, canonical)
		}
	}
}

func TestUnsupportedTLSParsePreservesSpellingHasValue(t *testing.T) {
	cases := []struct {
		input, name, spelling, value string
		has                          bool
	}{
		{"OPENSSL:localhost:443,fips", "openssl-fips", "fips", "", false},
		{"OPENSSL:localhost:443,fips=1", "openssl-fips", "fips", "1", true},
		{"OPENSSL:localhost:443,fips=", "openssl-fips", "fips", "", true},
		{"OPENSSL:localhost:443,METHOD=SSL3", "openssl-method", "method", "SSL3", true},
		{"OPENSSL:localhost:443,egd=/tmp/egd", "openssl-egd", "egd", "/tmp/egd", true},
		{"OPENSSL:localhost:443,maxfraglen=-1", "openssl-maxfraglen", "maxfraglen", "-1", true},
		{"OPENSSL:localhost:443,openssl-dhparams=dh.pem", "openssl-dhparam", "openssl-dhparams", "dh.pem", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			s, err := ParseSpec(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Options) != 1 {
				t.Fatalf("options=%v", s.Options)
			}
			o := s.Options[0]
			if o.Name != tc.name || o.Spelling != tc.spelling || o.Has != tc.has || o.Value != tc.value {
				t.Fatalf("got Name=%q Spelling=%q Has=%v Value=%q", o.Name, o.Spelling, o.Has, o.Value)
			}
		})
	}
}

func TestUnsupportedTLSUnknownTyposStayUnfolded(t *testing.T) {
	for _, name := range []string{"fipss", "openssl-metod", "maxfraglenn", "dhparamx"} {
		if got := CanonicalOptionName(name); got != name {
			t.Errorf("CanonicalOptionName(%q)=%q want unchanged", name, got)
		}
		s, err := ParseSpec("OPENSSL:localhost:443," + name)
		if err != nil {
			t.Fatal(err)
		}
		if s.Options[0].Name != name || s.Options[0].Spelling != name {
			t.Errorf("%s folded to Name=%q Spelling=%q", name, s.Options[0].Name, s.Options[0].Spelling)
		}
	}
}

func TestConstructedSpecAliasNameFolds(t *testing.T) {
	s := Spec{Type: "OPENSSL", Options: []Option{{Name: "fips"}}}
	if !s.HasOption("openssl-fips") || !s.BoolOption("fips") {
		t.Fatalf("constructed Name=fips must fold: %+v", s.Options)
	}
	if CanonicalOptionName("fips") != "openssl-fips" {
		t.Fatal("fips must fold onto openssl-fips")
	}
}

func TestPublicTLSAliasesRemainOutsidePilot(t *testing.T) {
	if CanonicalOptionName("compress") != "openssl-compress" {
		t.Fatalf("compress=%q", CanonicalOptionName("compress"))
	}
	if CanonicalOptionName("certificate") != "cert" {
		t.Fatalf("certificate=%q", CanonicalOptionName("certificate"))
	}
}

func TestEGDAndDHParamAreNotPathOptions(t *testing.T) {
	for _, name := range []string{
		"egd", "openssl-egd", "dhparam", "dhparams", "dh", "openssl-dhparam", "openssl-dhparams",
	} {
		if pathOption(name) {
			t.Errorf("%s must not use Windows path syntax", name)
		}
	}
	if !pathOption("cert") {
		t.Fatal("cert remains a path option")
	}
}
