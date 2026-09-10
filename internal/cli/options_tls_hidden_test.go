package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestHiddenTLSSpellingsAreRecognized(t *testing.T) {
	table := buildSupportedAddressOptions()
	for _, name := range []string{
		"openssl-method", "opensslmethod", "method",
		"openssl-fips", "fips", "openssl-egd", "egd",
		"openssl-pseudo", "pseudo", "openssl-dhparam", "openssl-dhparams",
		"dhparam", "dhparams", "dh", "openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	} {
		if _, ok := table[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
}

func TestHiddenTLSOptionValues(t *testing.T) {
	for _, spec := range []string{"OPENSSL:h:1,fips=0", "OPENSSL:h:1,method=TLS1", "OPENSSL:h:1,maxfraglen=-1"} {
		if err := validateParsed(t, spec); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
	err := validateParsed(t, "OPENSSL:h:1,method")
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("bare method: %v", err)
	}
	err = validateParsed(t, "OPENSSL:h:1,fips=2,fips=1")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("earlier fips=2: %v", err)
	}
	err = validateParsed(t, "TCP4:127.0.0.1:1,fips=1")
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("TCP4 fips: %v", err)
	}
}

func TestHiddenTLSNamesStayOutOfHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelp(&buf, 3); err != nil {
		t.Fatal(err)
	}
	listed := helpLineNames(buf.String())
	if listed["fips"] || listed["openssl-method"] {
		t.Fatal("-hhh advertises a hidden TLS option")
	}
	if !listed["openssl-compress"] || !listed["compress"] {
		t.Fatal("-hhh missing openssl-compress")
	}
}

func TestConstructedFIPSNameIsRecognized(t *testing.T) {
	err := validateSpecOptions(parse.Spec{Type: "OPENSSL", Options: []parse.Option{{Name: "fips"}}})
	if err != nil {
		t.Fatal(err)
	}
}

func validateParsed(t *testing.T, spec string) error {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	return validateChannelOptions(ch)
}
