package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestHelpDoesNotTriggerClassicOptionArraySentinel(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	// Classic test.sh uses the loose expression /opt:/ as an internal-help
	// sentinel. Human-readable descriptions must not accidentally match it.
	if strings.Contains(output.String(), "opt:") {
		t.Fatal("-hhh output contains classic test.sh's internal option-array sentinel \"opt:\"")
	}
}

func TestHelpListsSoBroadcastAlias(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, name := range []string{"broadcast", "so-broadcast"} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("-hhh missing %q", name)
		}
	}
	if !strings.Contains(help, "alias of broadcast") {
		t.Error("-hhh missing so-broadcast alias line")
	}
}

func TestHelpListsDescriptorLifecycleAliases(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	canonical := []string{"perm", "ftruncate"}
	aliases := map[string]string{
		"mode":        "perm",
		"truncate":    "ftruncate",
		"ftruncate32": "ftruncate",
		"ftruncate64": "ftruncate",
	}
	// Windows has no fchmod/fchown on inherited FDs; user/group stay
	// rejected and hidden from -hhh (same rule as membership). Unix
	// advertises classic uid/owner/gid spellings.
	if runtime.GOOS != "windows" {
		canonical = append(canonical, "user", "group")
		aliases["uid"] = "user"
		aliases["owner"] = "user"
		aliases["gid"] = "group"
	}
	for _, name := range canonical {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("-hhh missing canonical %q", name)
		}
	}
	for alias, canon := range aliases {
		want := "alias of " + canon
		found := false
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == alias && strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("-hhh missing %q as %s", alias, want)
		}
	}
}

func TestHelpListsTLSPublicAliases(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	canonical := []string{
		"cert", "key", "cafile", "verify", "commonname", "nosni", "ciphers",
		"openssl-min-proto-version", "openssl-max-proto-version",
	}
	aliases := map[string]string{
		"certificate":         "cert",
		"openssl-certificate": "cert",
		"openssl-key":         "key",
		"openssl-cafile":      "cafile",
		"openssl-verify":      "verify",
		"cn":                  "commonname",
		"cipherlist":          "ciphers",
		"no-sni":              "nosni",
		"min-proto-version":   "openssl-min-proto-version",
		"max-proto-version":   "openssl-max-proto-version",
	}
	for _, name := range canonical {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("-hhh missing canonical %q", name)
		}
	}
	for alias, canon := range aliases {
		want := "alias of " + canon
		found := false
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == alias && strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("-hhh missing %q as %s", alias, want)
		}
	}
}

func TestHelpDoesNotAdvertiseUnsupportedOpenSSL(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, name := range []string{
		"openssl-method", "opensslmethod", "method",
		"openssl-fips", "fips",
		"openssl-compress", "compress",
		"openssl-egd", "egd",
		"openssl-pseudo", "pseudo",
		"openssl-dhparam", "dhparam", "dhparams", "dh",
		"openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	} {
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == name {
				t.Errorf("-hhh advertises unsupported OpenSSL option %q: %s", name, strings.TrimSpace(line))
			}
		}
	}
}
