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
		{"binary", "windows", ClassMustAdvertise},
		{"binary", "linux", ClassForeign},
		{"text", "windows", ClassMustAdvertise},
		{"text", "darwin", ClassForeign},
		{"noinherit", "windows", ClassMustAdvertise},
		{"bin", "windows", ClassMustAdvertise},
		{"o-binary", "linux", ClassForeign},
		{"o-text", "windows", ClassMustAdvertise},
		{"o-noinherit", "darwin", ClassForeign},
		{"nopush", "darwin", ClassExpectedMissing},
		{"nopush", "linux", ClassForeign},
		{"ip-recvif", "darwin", ClassExpectedMissing},
		{"ip-recvif", "linux", ClassForeign},
		{"fs-append", "linux", ClassMustAdvertise},
		{"fs-append", "windows", ClassMustAdvertise},
		{"notail", "linux", ClassMustAdvertise},
		{"notail", "windows", ClassMustAdvertise},
		{"sctp-nodelay", "linux", ClassMustAdvertise},
		{"sctp-nodelay", "darwin", ClassMustAdvertise},
		{"sctp-nodelay", "windows", ClassMustAdvertise},
		{"so-priority", "linux", ClassMustAdvertise},
		{"so-priority", "darwin", ClassMustAdvertise},
		{"so-priority", "windows", ClassMustAdvertise},
		{"priority", "linux", ClassMustAdvertise},
		{"so-passcred", "linux", ClassMustAdvertise},
		{"so-no-check", "linux", ClassMustAdvertise},
		{"nocheck", "linux", ClassMustAdvertise},
		{"no-check", "linux", ClassMustAdvertise},
		{"dash", "linux", ClassMustAdvertise},
		{"dash", "darwin", ClassMustAdvertise},
		{"dash", "windows", ClassMustAdvertise},
		{"login", "linux", ClassMustAdvertise},
		{"setpgid", "linux", ClassMustAdvertise},
		{"setpgid", "windows", ClassMustAdvertise},
		{"pgid", "linux", ClassMustAdvertise},
		{"sighup", "linux", ClassMustAdvertise},
		{"sighup", "darwin", ClassMustAdvertise},
		{"sighup", "windows", ClassMustAdvertise},
		{"sigint", "linux", ClassMustAdvertise},
		{"sigquit", "linux", ClassMustAdvertise},
		{"sctp-maxseg", "linux", ClassMustAdvertise},
		{"sctp-maxseg", "darwin", ClassMustAdvertise},
		{"sctp-maxseg", "windows", ClassMustAdvertise},
		{"sctp-maxseg-late", "linux", ClassOptionalParserOnly},
		{"abort-threshold", "linux", ClassForeign},
		{"abort-threshold", "windows", ClassForeign},
		{"cr", "linux", ClassMustAdvertise},
		{"cr", "windows", ClassMustAdvertise},
		{"shut-down", "linux", ClassMustAdvertise},
		{"shut-down", "windows", ClassMustAdvertise},
		{"udp-ignore-peerport", "linux", ClassUnsupported},
		{"udp-ignore-peerport", "darwin", ClassUnsupported},
		{"udp-ignore-peerport", "windows", ClassUnsupported},
		{"udplite-send-cscov", "linux", ClassMustAdvertise},
		{"udplite-recv-cscov", "linux", ClassMustAdvertise},
		{"udplite-send-cscov", "darwin", ClassMustAdvertise},
		{"udplite-send-cscov", "windows", ClassMustAdvertise},
		{"ioctl", "linux", ClassMustAdvertise},
		{"ioctl", "darwin", ClassMustAdvertise},
		{"ioctl", "windows", ClassMustAdvertise},
		{"ioctl-void", "linux", ClassMustAdvertise},
		{"ioctl-void", "darwin", ClassMustAdvertise},
		{"ioctl-void", "windows", ClassMustAdvertise},
		{"ioctl-int", "linux", ClassMustAdvertise},
		{"ioctl-int", "darwin", ClassMustAdvertise},
		{"ioctl-int", "windows", ClassMustAdvertise},
		{"ioctl-intp", "linux", ClassMustAdvertise},
		{"ioctl-intp", "darwin", ClassMustAdvertise},
		{"ioctl-intp", "windows", ClassMustAdvertise},
		{"ioctl-bin", "linux", ClassMustAdvertise},
		{"ioctl-bin", "darwin", ClassMustAdvertise},
		{"ioctl-bin", "windows", ClassMustAdvertise},
		{"ioctl-string", "linux", ClassMustAdvertise},
		{"ioctl-string", "darwin", ClassMustAdvertise},
		{"ioctl-string", "windows", ClassMustAdvertise},
		{"cloexec", "linux", ClassMustAdvertise},
		{"cloexec", "darwin", ClassMustAdvertise},
		{"cloexec", "windows", ClassMustAdvertise},
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
	if _, ok := linux["udp-ignore-peerport"]; ok {
		t.Fatal("linux backlog must not include udp-ignore-peerport (documented but never implemented by classic)")
	}
	if _, ok := linux["udplite-send-cscov"]; ok {
		t.Fatal("linux backlog must not include implemented udplite-send-cscov (#101)")
	}
	if _, ok := linux["udplite-recv-cscov"]; ok {
		t.Fatal("linux backlog must not include implemented udplite-recv-cscov (#101)")
	}
	if _, ok := linux["sctp-nodelay"]; ok {
		t.Fatal("linux backlog must not include implemented sctp-nodelay")
	}
	if _, ok := linux["sctp-maxseg"]; ok {
		t.Fatal("linux backlog must not include implemented sctp-maxseg")
	}
	if _, ok := linux["fs-append"]; ok {
		t.Fatal("linux backlog must not include implemented fs-append")
	}
	if _, ok := linux["notail"]; ok {
		t.Fatal("linux backlog must not include implemented notail")
	}
	if _, ok := linux["binary"]; ok {
		t.Fatal("linux backlog must not include Windows-only binary")
	}
	win := ImplementationBacklog("windows")
	if _, ok := win["binary"]; ok {
		t.Fatal("windows backlog must not include implemented binary")
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
	if _, ok := darwin["sctp-nodelay"]; ok {
		t.Fatal("darwin backlog must not include implemented sctp-nodelay")
	}
	if _, ok := darwin["sctp-maxseg"]; ok {
		t.Fatal("darwin backlog must not include implemented sctp-maxseg")
	}
	if _, ok := win["sctp-nodelay"]; ok {
		t.Fatal("windows backlog must not include implemented sctp-nodelay")
	}
	if _, ok := win["sctp-maxseg"]; ok {
		t.Fatal("windows backlog must not include implemented sctp-maxseg")
	}
	if _, ok := win["udplite-recv-cscov"]; ok {
		t.Fatal("windows backlog must not include Linux UDP-Lite cscov")
	}
}

func TestAddressClassificationSeparatesUnsupportedFromAliases(t *testing.T) {
	class, _ := ClassifyAddress("ABSTRACT", "linux")
	if class != AddrMustRegister {
		t.Fatalf("ABSTRACT: %s (resolved to ABSTRACT-CLIENT by PR C)", class)
	}
	class, _ = ClassifyAddress("UDP-DGRAM", "linux")
	if class != AddrMustRegister {
		t.Fatalf("UDP-DGRAM: %s (resolved to UDP-DATAGRAM by PR C)", class)
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
	if class != AddrMustRegister {
		t.Fatalf("ACCEPT-FD on linux: %s (implemented PR F)", class)
	}
	class, _ = ClassifyAddress("ACCEPT-FD", "windows")
	if class != AddrMustRegister {
		t.Fatalf("ACCEPT-FD on windows: %s (registered, help hidden like UDPLITE)", class)
	}
	class, _ = ClassifyAddress("ACCEPT", "linux")
	if class != AddrMustRegister {
		t.Fatalf("ACCEPT alias: %s (registered with ACCEPT-FD)", class)
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
		t.Fatalf("UDPLITE-DGRAM: %s (registered with the family in #101)", class)
	}
	class, _ = ClassifyAddress("UDPLITE-CONNECT", "darwin")
	if class != AddrMustRegister {
		t.Fatalf("UDPLITE-CONNECT on darwin: %s (registered, FeatureUDPLITE-gated like VSOCK)", class)
	}
	if _, ok := ExpectedMissingCanonicalAddresses["UDPLITE-CONNECT"]; ok {
		t.Fatal("UDPLITE-CONNECT is implemented (#101); remove it from ExpectedMissingCanonicalAddresses")
	}
	if got := len(ExpectedMissingCanonicalAddresses); got != 0 {
		t.Fatalf("expected-missing canonicals=%d, want 0", got)
	}
	class, _ = ClassifyAddress("-", runtime.GOOS)
	if class != AddrParserShorthand {
		t.Fatalf("-: %s", class)
	}
	if _, ok := ExpectedMissingAddressAliases["ACCEPT"]; ok {
		t.Fatal("ACCEPT must not be in the supported-alias backlog; ACCEPT-FD is implemented")
	}
	if _, ok := ExpectedMissingAddressAliases["UDPLITE"]; ok {
		t.Fatal("UDPLITE must not be in the supported-alias backlog")
	}
	if _, ok := ExpectedMissingAddressAliases["DCCP"]; ok {
		t.Fatal("DCCP must not be in the supported-alias backlog")
	}
	if got := len(ExpectedMissingAddressAliases); got != 0 {
		t.Fatalf("supported missing aliases=%d, want 0 (PR C resolved the backlog)", got)
	}
}

func TestDocsOnlyNamesAreClassified(t *testing.T) {
	for name := range DocsOnlyNotInThisBinary {
		class, reason := ClassifyOption(name, "linux")
		switch class {
		case ClassMustAdvertise:
			// This port implements dump-omitted documented names (notail, sctp-nodelay).
		case ClassExpectedMissing, ClassUnsupported, ClassForeign:
			if reason == "" {
				t.Errorf("docs-only %q classified %s with empty reason", name, class)
			}
		default:
			t.Errorf("docs-only %q class=%s; need expected-missing, unsupported, foreign, or must-advertise", name, class)
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

func TestIgnoreCRIsMustAdvertise(t *testing.T) {
	if _, ok := ExpectedMissingAll()["ignorecr"]; ok {
		t.Fatal("ignorecr must not remain expected-missing after HTTP/1 CONNECT parser support")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		class, reason := ClassifyOption("ignorecr", goos)
		if class != ClassMustAdvertise {
			t.Errorf("%s: class=%s reason=%q; want must-advertise", goos, class, reason)
		}
		if _, ok := ImplementationBacklog(goos)["ignorecr"]; ok {
			t.Errorf("%s backlog still lists ignorecr", goos)
		}
	}
}

func TestUDPIgnorePeerportIsUnsupportedNotBacklog(t *testing.T) {
	if _, ok := DocsOnlyNotInThisBinary["udp-ignore-peerport"]; !ok {
		t.Fatal("udp-ignore-peerport must stay in DocsOnlyNotInThisBinary")
	}
	if _, ok := ExpectedMissingAll()["udp-ignore-peerport"]; ok {
		t.Fatal("udp-ignore-peerport must not be expected-missing; classic C never implemented it")
	}
	if _, ok := RequiredPublicSpellings()["udp-ignore-peerport"]; !ok {
		t.Fatal("documented udp-ignore-peerport stays in RequiredPublicSpellings; ClassifyOption marks it unsupported")
	}
	reason, ok := UnsupportedPublic()["udp-ignore-peerport"]
	if !ok {
		t.Fatal("udp-ignore-peerport must be in UnsupportedPublic")
	}
	if strings.TrimSpace(reason) == "" {
		t.Fatal("udp-ignore-peerport unsupported reason is empty")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		class, classReason := ClassifyOption("udp-ignore-peerport", goos)
		if class != ClassUnsupported {
			t.Errorf("%s: class=%s reason=%q; want unsupported", goos, class, classReason)
		}
		if _, ok := ImplementationBacklog(goos)["udp-ignore-peerport"]; ok {
			t.Errorf("%s backlog includes udp-ignore-peerport; it is not an implementation item", goos)
		}
	}
}

func TestMergeStringMapsRejectsDuplicateNames(t *testing.T) {
	_, err := mergeStringMaps([]map[string]string{
		{"foo": "same reason"},
		{"foo": "same reason"},
	}, "unsupported option")
	if err == nil || !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "foo") {
		t.Fatalf("identical-reason duplicate should fail, got %v", err)
	}

	_, err = mergeStringMaps([]map[string]string{
		{"foo": "reason a"},
		{"foo": "reason b"},
	}, "unsupported option")
	if err == nil || !strings.Contains(err.Error(), "foo") {
		t.Fatalf("differing-reason duplicate should fail, got %v", err)
	}

	got, err := mergeStringMaps([]map[string]string{
		{"foo": "a"},
		{"bar": "b"},
	}, "unsupported option")
	if err != nil {
		t.Fatal(err)
	}
	if got["foo"] != "a" || got["bar"] != "b" || len(got) != 2 {
		t.Fatalf("unique names: %v", got)
	}

	_, err = mergeStringMaps([]map[string]string{
		{"foo": ""},
	}, "unsupported option")
	if err == nil || !strings.Contains(err.Error(), "without a reason") {
		t.Fatalf("empty reason should fail, got %v", err)
	}
}
