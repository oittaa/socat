package cli

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

func TestCatalogAliasesPreserveParsingValidationAndHelp(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	listed := helpLineNames(output.String())
	for _, tc := range []struct {
		spelling, canonical string
		advertised          bool
	}{
		{"tcp-nodelay", "nodelay", true},
		{"tcp-keepalive", "keepalive", false},
		{"linger", "linger", true},
	} {
		spec, err := parse.ParseSpec("TCP4:127.0.0.1:1," + tc.spelling + "=1")
		if err != nil {
			t.Fatal(err)
		}
		option := spec.Options[0]
		if option.Name != tc.canonical || option.OriginalSpelling() != tc.spelling || !option.Has || option.Value != "1" {
			t.Errorf("%s: parsed %+v", tc.spelling, option)
		}
		if err := validateSpecOptions(spec); err != nil {
			t.Errorf("%s: %v", tc.spelling, err)
		}
		if listed[tc.spelling] != tc.advertised {
			t.Errorf("%s: advertised=%v", tc.spelling, listed[tc.spelling])
		}
	}
}

func TestOptionApplicabilityIgnoresHelpSection(t *testing.T) {
	defs := optionmeta.All()
	for i := range defs {
		if defs[i].Canonical == "origin" {
			defs[i].Section = optionmeta.SectionTLS
		}
	}
	previous := supportedAddressOptions
	supportedAddressOptions = addressOptionsFromDefs(defs)
	t.Cleanup(func() { supportedAddressOptions = previous })
	for _, tc := range []struct {
		address  string
		accepted bool
	}{
		{"WS:127.0.0.1:80,origin=example", true},
		{"OPENSSL:127.0.0.1:443,origin=example", false},
	} {
		spec, err := parse.ParseSpec(tc.address)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSpecOptions(spec); (err == nil) != tc.accepted {
			t.Errorf("%s: accepted=%v, error=%v", tc.address, tc.accepted, err)
		}
	}
}
