package optionmeta

import "testing"

func TestCatalogRejectsDuplicates(t *testing.T) {
	opts := All()
	if err := validateCatalog(opts); err != nil {
		t.Fatal(err)
	}
	opts[0].Canonical = ""
	if err := validateCatalog(opts); err == nil {
		t.Fatal("empty canonical")
	}
}

func TestParserAliasIsNotAlwaysPublic(t *testing.T) {
	d, ok := Lookup("keepalive")
	if !ok {
		t.Fatal("missing keepalive")
	}
	if !contains(d.ParserAliases, "tcp-keepalive") {
		t.Fatalf("parser aliases %v", d.ParserAliases)
	}
	if contains(d.PublicAliases, "tcp-keepalive") {
		t.Fatal("tcp-keepalive must not be advertised")
	}
	if ParserCanonical("tcp-keepalive") != "keepalive" {
		t.Fatal("tcp-keepalive should fold")
	}
}

func TestPublicAliasIsNotAlwaysParser(t *testing.T) {
	d, ok := Lookup("so-linger")
	if !ok {
		t.Fatal("missing so-linger")
	}
	if !contains(d.PublicAliases, "linger") {
		t.Fatalf("public aliases %v", d.PublicAliases)
	}
	if contains(d.ParserAliases, "linger") {
		t.Fatal("linger must not fold at parse")
	}
	if ParserCanonical("linger") != "linger" {
		t.Fatal("linger must stay linger")
	}
	if _, ok := Lookup("linger"); !ok {
		t.Fatal("CLI must still recognize linger")
	}
}

func TestTLSApplicabilityIsNotHelpTitle(t *testing.T) {
	d, ok := Lookup("cert")
	if !ok {
		t.Fatal("missing cert")
	}
	if d.Section != SectionTLS {
		t.Fatalf("section %q", d.Section)
	}
	if !contains(d.Apply.AddressGroups, GroupProxy) {
		t.Fatalf("cert groups %v", d.Apply.AddressGroups)
	}
	d.Section = "renamed heading"
	if !contains(d.Apply.AddressGroups, GroupProxy) {
		t.Fatal("renaming a heading must not clear applicability")
	}
}

func TestPublicTLSCanonicals(t *testing.T) {
	got := PublicTLSCanonicals()
	want := []string{
		"cert", "key", "cafile", "capath", "verify", "commonname",
		"snihost", "nosni", "ciphers", "openssl-compress",
		"openssl-min-proto-version", "openssl-max-proto-version", "alpn",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestAncillaryFamilyCount(t *testing.T) {
	got := AncillaryCanonicals()
	if len(got) != 21 {
		t.Fatalf("ancillary families=%d %v", len(got), got)
	}
}

func TestIsolationAndGetOnlyStayHidden(t *testing.T) {
	for _, name := range []string{"setuid", "su", "ip-mtu", "mtu", "openssl-method", "fips"} {
		d, ok := Lookup(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if d.Help != HelpHidden {
			t.Errorf("%s advertised", name)
		}
	}
}

func TestPathValue(t *testing.T) {
	if !IsPathValue("cert") || !IsPathValue("chdir") {
		t.Fatal("path options")
	}
	if IsPathValue("egd") || IsPathValue("openssl-egd") {
		t.Fatal("egd must not be a path option")
	}
}

func TestHiddenOnUsesAdvertiseNotHeading(t *testing.T) {
	cases := []struct {
		name, goos string
		hidden     bool
	}{
		{"binary", "windows", false},
		{"binary", "linux", true},
		{"nopush", "darwin", false},
		{"nopush", "linux", true},
		{"so-sndlowat", "darwin", false},
		{"so-sndlowat", "linux", true},
		{"ioctl-void", "windows", true},
		{"ioctl-void", "linux", false},
		{"fs-append", "linux", false},
		{"fs-append", "darwin", true},
		{"pipes", "windows", true},
		{"pipes", "linux", false},
		{"reuseaddr", "linux", false},
		{"reuseaddr", "windows", false},
	}
	for _, tc := range cases {
		d, ok := Lookup(tc.name)
		if !ok {
			t.Fatalf("missing %s", tc.name)
		}
		if HiddenOn(d, tc.goos) != tc.hidden {
			t.Errorf("%s on %s: HiddenOn=%v want %v", tc.name, tc.goos, HiddenOn(d, tc.goos), tc.hidden)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
