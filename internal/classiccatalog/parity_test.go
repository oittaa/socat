package classiccatalog

import (
	"runtime"
	"strings"
	"testing"
)

func TestValidateParityManifests(t *testing.T) {
	if err := ValidateParityManifests(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSSLExclusionsAreUnsupportedNotBacklog(t *testing.T) {
	for _, name := range []string{
		"method", "fips",
		"openssl-egd", "egd", "openssl-pseudo", "pseudo",
		"openssl-dhparam", "dhparam", "dh", "dhparams",
		"openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	} {
		class, reason := ClassifyOption(name, "linux")
		if class != ClassUnsupported {
			t.Errorf("%q: class=%s reason=%q; want unsupported (must not be required-missing and must-not-advertise at once)",
				name, class, reason)
		}
		if reason == "" {
			t.Errorf("%q: unsupported OpenSSL option needs a reason", name)
		}
		if _, ok := ImplementationBacklog("linux")[name]; ok {
			t.Errorf("%q must not be in the Linux implementation backlog", name)
		}
		if _, ok := ImplementationBacklog("windows")[name]; ok {
			t.Errorf("%q must not be in the Windows implementation backlog", name)
		}
		if _, ok := OptionalParserOnlyAliases[name]; ok {
			t.Errorf("%q is a documented public spelling; keep parser-only openssl-method/openssl-fips separate", name)
		}
	}
	if _, ok := RequiredPublicSpellings()["method"]; !ok {
		t.Fatal("documented method stays in RequiredPublicSpellings; ClassifyOption marks it unsupported")
	}
	if _, ok := RequiredPublicSpellings()["fips"]; !ok {
		t.Fatal("documented fips stays in RequiredPublicSpellings; ClassifyOption marks it unsupported")
	}
	if _, ok := RequiredPublicSpellings()["openssl-method"]; ok {
		t.Fatal("openssl-method is parser-only")
	}
	if _, ok := RequiredPublicSpellings()["openssl-fips"]; ok {
		t.Fatal("openssl-fips is parser-only")
	}
}

func TestPlatformSpecificNamesStayRequiredOnTheirGOOS(t *testing.T) {
	tests := []struct {
		name, goos string
		want       OptionClass
	}{
		{"binary", "windows", ClassExpectedMissing},
		{"binary", "linux", ClassForeign},
		{"text", "windows", ClassExpectedMissing},
		{"text", "darwin", ClassForeign},
		{"noinherit", "windows", ClassExpectedMissing},
		{"nopush", "darwin", ClassExpectedMissing},
		{"nopush", "linux", ClassForeign},
		{"ip-recvif", "darwin", ClassExpectedMissing},
		{"ip-recvif", "linux", ClassForeign},
		{"fs-append", "linux", ClassExpectedMissing},
		{"fs-append", "windows", ClassForeign},
		{"sctp-nodelay", "linux", ClassExpectedMissing},
		{"sctp-nodelay", "darwin", ClassForeign},
		{"abort-threshold", "linux", ClassForeign},
		{"abort-threshold", "windows", ClassForeign},
		{"cr", "linux", ClassExpectedMissing},
		{"cr", "windows", ClassExpectedMissing},
		{"udp-ignore-peerport", "linux", ClassExpectedMissing},
		{"udplite-send-cscov", "linux", ClassMustAdvertise},
		{"udplite-recv-cscov", "linux", ClassMustAdvertise},
		{"udplite-send-cscov", "darwin", ClassMustAdvertise},
		{"udplite-send-cscov", "windows", ClassMustAdvertise},
		{"so-bsdcompat", "linux", ClassUnsupported},
		{"history-file", "linux", ClassUnsupported},
		{"dccp-set-ccid", "linux", ClassUnsupported},
		{"cool-write", "linux", ClassUnsupported},
	}
	for _, tc := range tests {
		got, reason := ClassifyOption(tc.name, tc.goos)
		if got != tc.want {
			t.Errorf("%s on %s: class=%s reason=%q; want %s", tc.name, tc.goos, got, reason, tc.want)
		}
		if (tc.want == ClassUnsupported || tc.want == ClassExpectedMissing || tc.want == ClassForeign) && reason == "" {
			t.Errorf("%s on %s: classified %s with empty reason", tc.name, tc.goos, got)
		}
	}
}

func TestImplementationBacklogOmitsExclusions(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		backlog := ImplementationBacklog(goos)
		for name := range UnsupportedPublic() {
			if _, ok := backlog[name]; ok {
				t.Errorf("%s backlog includes unsupported %q", goos, name)
			}
		}
		for name, gap := range ForeignPublic() {
			if _, ok := backlog[name]; ok {
				t.Errorf("%s backlog includes foreign %q (%s)", goos, name, gap.Reason)
			}
		}
	}
	linux := ImplementationBacklog("linux")
	if _, ok := linux["udp-ignore-peerport"]; !ok {
		t.Fatal("linux backlog must include documented udp-ignore-peerport")
	}
	if _, ok := linux["udplite-send-cscov"]; ok {
		t.Fatal("linux backlog must not include implemented udplite-send-cscov (#101)")
	}
	if _, ok := linux["udplite-recv-cscov"]; ok {
		t.Fatal("linux backlog must not include implemented udplite-recv-cscov (#101)")
	}
	if _, ok := linux["binary"]; ok {
		t.Fatal("linux backlog must not include Windows-only binary")
	}
	win := ImplementationBacklog("windows")
	if _, ok := win["binary"]; !ok {
		t.Fatal("windows backlog must include binary")
	}
	if _, ok := win["fs-append"]; ok {
		t.Fatal("windows backlog must not include Linux fs-append")
	}
	darwin := ImplementationBacklog("darwin")
	if _, ok := darwin["nopush"]; !ok {
		t.Fatal("darwin backlog must include nopush")
	}
	if _, ok := darwin["fs-append"]; ok {
		t.Fatal("darwin backlog must not include Linux fs-append")
	}
	if _, ok := darwin["udplite-send-cscov"]; ok {
		t.Fatal("darwin backlog must not include Linux UDP-Lite cscov")
	}
	if _, ok := win["udplite-recv-cscov"]; ok {
		t.Fatal("windows backlog must not include Linux UDP-Lite cscov")
	}
}

func TestAddressClassificationSeparatesUnsupportedFromAliases(t *testing.T) {
	class, _ := ClassifyAddress("ABSTRACT", "linux")
	if class != AddrExpectedMissingAlias {
		t.Fatalf("ABSTRACT: %s", class)
	}
	class, _ = ClassifyAddress("DCCP", "linux")
	if class != AddrUnsupportedFamily {
		t.Fatalf("DCCP: %s", class)
	}
	class, _ = ClassifyAddress("DTLS", "linux")
	if class != AddrUnsupportedFamily {
		t.Fatalf("DTLS: %s", class)
	}
	class, _ = ClassifyAddress("READLINE", "linux")
	if class != AddrUnsupportedFamily {
		t.Fatalf("READLINE: %s", class)
	}
	class, _ = ClassifyAddress("ACCEPT-FD", "linux")
	if class != AddrExpectedMissingCanonical {
		t.Fatalf("ACCEPT-FD on linux: %s", class)
	}
	class, _ = ClassifyAddress("ACCEPT-FD", "windows")
	if class != AddrForeign {
		t.Fatalf("ACCEPT-FD on windows: %s (Unix-only)", class)
	}
	class, _ = ClassifyAddress("UDPLITE-CONNECT", "linux")
	if class != AddrMustRegister {
		t.Fatalf("UDPLITE-CONNECT: %s (implemented in #101)", class)
	}
	class, _ = ClassifyAddress("UDPLITE", "linux")
	if class != AddrMustRegister {
		t.Fatalf("UDPLITE alias: %s (registered with the family in #101)", class)
	}
	class, _ = ClassifyAddress("UDPLITE-DGRAM", "linux")
	if class != AddrMustRegister {
		t.Fatalf("UDPLITE-DGRAM: %s (registered with the family in #101; UDP-DGRAM remains alias backlog)", class)
	}
	class, _ = ClassifyAddress("UDPLITE-CONNECT", "darwin")
	if class != AddrMustRegister {
		t.Fatalf("UDPLITE-CONNECT on darwin: %s (registered, FeatureUDPLITE-gated like VSOCK)", class)
	}
	if _, ok := ExpectedMissingCanonicalAddresses["UDPLITE-CONNECT"]; ok {
		t.Fatal("UDPLITE-CONNECT is implemented (#101); remove it from ExpectedMissingCanonicalAddresses")
	}
	if got := len(ExpectedMissingCanonicalAddresses); got != 1 {
		t.Fatalf("expected-missing canonicals=%d, want 1 (ACCEPT-FD)", got)
	}
	class, _ = ClassifyAddress("-", runtime.GOOS)
	if class != AddrParserShorthand {
		t.Fatalf("-: %s", class)
	}
	if _, ok := ExpectedMissingAddressAliases["ACCEPT"]; ok {
		t.Fatal("ACCEPT must not be in the supported-alias backlog; its canonical ACCEPT-FD is unimplemented")
	}
	if _, ok := ExpectedMissingAddressAliases["UDPLITE"]; ok {
		t.Fatal("UDPLITE must not be in the supported-alias backlog")
	}
	if _, ok := ExpectedMissingAddressAliases["DCCP"]; ok {
		t.Fatal("DCCP must not be in the supported-alias backlog")
	}
	if got := len(ExpectedMissingAddressAliases); got != 26 {
		t.Fatalf("supported missing aliases=%d, want 26", got)
	}
}

func TestDocsOnlyNamesAreClassified(t *testing.T) {
	for name := range DocsOnlyNotInThisBinary {
		class, reason := ClassifyOption(name, "linux")
		switch class {
		case ClassExpectedMissing, ClassUnsupported, ClassForeign:
			if reason == "" {
				t.Errorf("docs-only %q classified %s with empty reason", name, class)
			}
		default:
			t.Errorf("docs-only %q class=%s; need expected-missing, unsupported, or foreign", name, class)
		}
	}
}

func TestExpectedMissingReasonsNonEmpty(t *testing.T) {
	for name, gap := range ExpectedMissingAll() {
		if strings.TrimSpace(gap.Reason) == "" {
			t.Errorf("expected-missing %q has no reason", name)
		}
	}
}
