package cli

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestUnsupportedTLSSpellingsRecognized(t *testing.T) {
	spellings := []string{
		"openssl-method", "opensslmethod", "method",
		"openssl-fips", "fips",
		"openssl-egd", "egd",
		"openssl-pseudo", "pseudo",
		"openssl-dhparam", "openssl-dhparams", "dhparam", "dhparams", "dh",
		"openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	}
	if len(spellings) != 18 {
		t.Fatalf("spelling count=%d want 18", len(spellings))
	}
	table := buildSupportedAddressOptions()
	wantGroups := tlsOptionAddressGroups()
	for _, name := range spellings {
		got, ok := table[name]
		if !ok {
			t.Fatalf("option table missing %q", name)
		}
		if !slices.Equal(got.addressGroups, wantGroups) {
			t.Errorf("%s addressGroups=%v want %v", name, got.addressGroups, wantGroups)
		}
		if !slices.Equal(got.optionCaps, capOpenSSL) {
			t.Errorf("%s optionCaps=%v want %v", name, got.optionCaps, capOpenSSL)
		}
		if len(got.addressTypes) != 0 || got.restrictAddressTypes || len(got.implementationGroups) != 0 {
			t.Errorf("%s extra constraints changed: %+v", name, got)
		}
		spec := "OPENSSL:localhost:443," + name + valueForTLSCLITest(name)
		if err := validateCLISpec(t, spec); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestUnsupportedTLSCLIValueContracts(t *testing.T) {
	t.Run("required string", func(t *testing.T) {
		for _, spec := range []string{
			"OPENSSL:localhost:443,method=TLS1",
			"OPENSSL:localhost:443,egd=/tmp/egd",
			"OPENSSL:localhost:443,dhparam=dh.pem",
		} {
			if err := validateCLISpec(t, spec); err != nil {
				t.Errorf("%s: %v", spec, err)
			}
		}
		for _, spec := range []string{
			"OPENSSL:localhost:443,method",
			"OPENSSL:localhost:443,method=",
			"OPENSSL:localhost:443,egd",
			"OPENSSL:localhost:443,dhparam=",
		} {
			err := validateCLISpec(t, spec)
			if err == nil || !strings.Contains(err.Error(), "requires a value") {
				t.Errorf("%s error=%v want requires a value", spec, err)
			}
		}
	})
	t.Run("optional bool", func(t *testing.T) {
		for _, spec := range []string{
			"OPENSSL:localhost:443,fips",
			"OPENSSL:localhost:443,fips=0",
			"OPENSSL:localhost:443,fips=1",
			"OPENSSL:localhost:443,pseudo",
			"OPENSSL:localhost:443,pseudo=0",
			"OPENSSL:localhost:443,openssl-pseudo=1",
		} {
			if err := validateCLISpec(t, spec); err != nil {
				t.Errorf("%s: %v", spec, err)
			}
		}
		for _, spec := range []string{
			"OPENSSL:localhost:443,fips=true",
			"OPENSSL:localhost:443,fips=false",
			"OPENSSL:localhost:443,pseudo=2",
			"OPENSSL:localhost:443,openssl-fips=off",
		} {
			err := validateCLISpec(t, spec)
			if err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Errorf("%s error=%v want invalid", spec, err)
			}
		}
	})
	t.Run("optional signed integer", func(t *testing.T) {
		for _, spec := range []string{
			"OPENSSL:localhost:443,maxfraglen",
			"OPENSSL:localhost:443,maxfraglen=512",
			"OPENSSL:localhost:443,maxfraglen=-1",
			"OPENSSL:localhost:443,openssl-maxsendfrag=0x10",
			"OPENSSL:localhost:443,maxsendfrag",
		} {
			if err := validateCLISpec(t, spec); err != nil {
				t.Errorf("%s: %v", spec, err)
			}
		}
		for _, spec := range []string{
			"OPENSSL:localhost:443,maxfraglen=x",
			"OPENSSL:localhost:443,maxsendfrag=",
			"OPENSSL:localhost:443,openssl-maxfraglen=1.5",
		} {
			err := validateCLISpec(t, spec)
			if err == nil {
				t.Errorf("%s succeeded", spec)
			}
		}
	})
}

func TestUnsupportedTLSMalformedEarlierDuplicateStillFails(t *testing.T) {
	err := validateCLISpec(t, "OPENSSL:localhost:443,fips=2,fips=1")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error=%v want invalid earlier fips=2", err)
	}
	err = validateCLISpec(t, "OPENSSL:localhost:443,method,method=TLS1")
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("error=%v want required value on earlier method", err)
	}
}

func TestUnsupportedTLSRejectedOnUnrelatedAddress(t *testing.T) {
	err := validateCLISpec(t, "TCP4:127.0.0.1:1,fips=1")
	if err == nil || !strings.Contains(err.Error(), "not supported with this address type") {
		t.Fatalf("error=%v want address-type rejection", err)
	}
	err = validateCLISpec(t, "TCP4:127.0.0.1:1,not-a-tls-option=1")
	if err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("error=%v want unknown option", err)
	}
}

func TestConstructedSpecAliasNameIsRecognized(t *testing.T) {
	spec := parse.Spec{
		Type:    "OPENSSL",
		Options: []parse.Option{{Name: "fips"}},
	}
	if err := validateSpecOptions(spec); err != nil {
		t.Fatalf("constructed Name=fips: %v", err)
	}
}

func TestUnsupportedTLSNamesStayHiddenInHelp(t *testing.T) {
	hidden := []string{
		"openssl-method", "opensslmethod", "method",
		"openssl-fips", "fips",
		"openssl-egd", "egd",
		"openssl-pseudo", "pseudo",
		"openssl-dhparam", "openssl-dhparams", "dhparam", "dhparams", "dh",
		"openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	}
	for _, level := range []int{2, 3} {
		var buf bytes.Buffer
		if err := printHelp(&buf, level); err != nil {
			t.Fatal(err)
		}
		help := buf.String()
		listed := helpLineNames(help)
		for _, name := range hidden {
			if listed[name] {
				t.Errorf("-%s advertises %q", strings.Repeat("h", level), name)
			}
		}
		if !listed["openssl-compress"] {
			t.Errorf("-%s missing openssl-compress", strings.Repeat("h", level))
		}
		if level == 3 && !listed["compress"] {
			t.Error("-hhh missing compress alias")
		}
		if level == 2 && listed["compress"] {
			t.Error("-hh must not list parser-only alias compress as a top-level option")
		}
	}
}

func TestValidatorForTLSCLIValueRejectsUnknownKind(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unknown kind must panic")
		}
	}()
	_ = validatorForTLSCLIValue(0)
}

func TestUnsupportedTLSCLIDoesNotUseRuntimeBoolForms(t *testing.T) {
	if err := validateCLISpec(t, "OPENSSL:localhost:443,fips=false"); err == nil {
		t.Fatal("CLI must not accept fips=false; only omission/0/1")
	}
}

func validateCLISpec(t *testing.T, spec string) error {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	return validateChannelOptions(ch)
}

func valueForTLSCLITest(name string) string {
	switch parse.CanonicalOptionName(name) {
	case "openssl-method", "openssl-egd", "openssl-dhparam":
		return "=x"
	default:
		return ""
	}
}
