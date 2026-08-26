package classiccatalog

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func testdataHHH(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	p := filepath.Join(filepath.Dir(file), "testdata", "tag-1.8.1.3.hhh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseHHHMatchesGeneratedCatalog(t *testing.T) {
	got, err := ParseHHHOptions(testdataHHH(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, Options) {
		if len(got) != len(Options) {
			t.Fatalf("parsed %d entries, generated catalog has %d", len(got), len(Options))
		}
		for spelling, want := range Options {
			have, ok := got[spelling]
			if !ok {
				t.Errorf("parsed dump missing %q", spelling)
				continue
			}
			if !reflect.DeepEqual(have, want) {
				t.Errorf("%q: dump=%+v catalog=%+v", spelling, have, want)
			}
		}
		for spelling := range got {
			if _, ok := Options[spelling]; !ok {
				t.Errorf("dump has extra spelling %q", spelling)
			}
		}
	}
}

func TestExtractClassicHelpMatchesCheckedInCatalog(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	dir := filepath.Dir(file)
	script := filepath.Join(dir, "../../scripts/extract-classic-help.py")
	dump := filepath.Join(dir, "testdata", "tag-1.8.1.3.hhh")
	py, err := exec.LookPath("python3")
	if err != nil {
		py, err = exec.LookPath("python")
		if err != nil {
			t.Skip("python3 is required to run the classic help generator")
		}
	}
	cmd := exec.Command(py, script, dump)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("extract-classic-help.py: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	fmtCmd := exec.Command("gofmt")
	fmtCmd.Stdin = bytes.NewReader(out)
	formatted, err := fmtCmd.Output()
	if err != nil {
		t.Fatalf("gofmt: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "catalog_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(formatted) != string(want) {
		t.Fatal("generated output differs from checked-in catalog_gen.go; regenerate from testdata/tag-1.8.1.3.hhh with gofmt on the Linux make-check VM (go.mod toolchain; CI lint runs make fmt-check)")
	}
}

func TestClassicHHHKeyEntries(t *testing.T) {
	tests := []struct {
		spelling  string
		canonical string
		groups    []string
		phase     string
		typ       string
		alias     bool
	}{
		{"ipv6-join-group", "ipv6-join-group", []string{"IP6"}, "PASTSOCKET", "STRUCT-IP_MREQN", false},
		{"ip-add-membership", "ip-add-membership", []string{"IP4", "IP6"}, "PASTSOCKET", "STRUCT-IP_MREQN", false},
		{"so-type", "so-type", []string{"SOCKET"}, "SOCKET", "INT", false},
		{"type", "so-type", []string{"SOCKET"}, "SOCKET", "INT", true},
		{"socktype", "so-type", []string{"SOCKET"}, "SOCKET", "INT", true},
		{"protocol", "so-protocol", []string{"SOCKET"}, "SOCKET", "INT", true},
		{"so-protocol", "so-protocol", []string{"SOCKET"}, "SOCKET", "INT", false},
		{"append", "append", []string{"FD", "OPEN"}, "LATE", "BOOL", false},
		{"o-append", "append", []string{"FD", "OPEN"}, "LATE", "BOOL", true},
		{"ftruncate", "ftruncate64", []string{"REG"}, "LATE", "OFF64_T", true},
		{"perm", "perm", []string{"FD", "NAMED"}, "FD", "MODE_T", false},
		{"user", "user", []string{"FD", "NAMED"}, "FD", "UID_T", false},
		{"group", "group", []string{"FD", "NAMED"}, "FD", "GID_T", false},
		{"so-broadcast", "so-broadcast", []string{"SOCKET"}, "PASTSOCKET", "INT", false},
		{"broadcast", "so-broadcast", []string{"SOCKET"}, "PASTSOCKET", "INT", true},
		{"setsockopt", "setsockopt", []string{"SOCKET"}, "CONNECTED", "INT:INT:BIN", false},
		{"setsockopt-int", "setsockopt-int", []string{"SOCKET"}, "CONNECTED", "INT:INT:INT", false},
		{"setsockopt-listen", "setsockopt-listen", []string{"SOCKET"}, "PREBIND", "INT:INT:BIN", false},
		{"setsockopt-socket", "setsockopt-socket", []string{"SOCKET"}, "PASTSOCKET", "INT:INT:BIN", false},
		{"setsockopt-connected", "setsockopt-connected", []string{"SOCKET"}, "CONNECTED", "INT:INT:BIN", false},
		{"sourceport", "sourceport", []string{"UDP", "TCP", "SCTP", "DCCP", "UDPLITE"}, "LATE", "UNSIGNED-SHORT", false},
		{"sp", "sourceport", []string{"UDP", "TCP", "SCTP", "DCCP", "UDPLITE"}, "LATE", "UNSIGNED-SHORT", true},
		{"lowport", "lowport", []string{"UDP", "TCP", "SCTP", "DCCP", "UDPLITE"}, "LATE", "BOOL", false},
		{"b7200", "b7200", []string{"TERMIOS"}, "FD", "CONST", false},
	}
	for _, tt := range tests {
		e, ok := Lookup(tt.spelling)
		if !ok {
			t.Errorf("%q missing from catalog", tt.spelling)
			continue
		}
		if e.Canonical != tt.canonical || e.Phase != tt.phase || e.Type != tt.typ || e.IsAlias() != tt.alias {
			t.Errorf("%q: canonical=%q phase=%q type=%q alias=%v", tt.spelling, e.Canonical, e.Phase, e.Type, e.IsAlias())
		}
		if !reflect.DeepEqual(e.Groups, tt.groups) {
			t.Errorf("%q groups=%v want %v", tt.spelling, e.Groups, tt.groups)
		}
	}
	if _, ok := Lookup("handshake-timeout"); ok {
		t.Fatal("handshake-timeout is a Go extension and must not appear in the classic catalog")
	}
	if _, ok := Lookup("cool-write"); !ok {
		t.Fatal("classic advertises cool-write; the catalog must record it (Go must not re-advertise it)")
	}
}

func TestSpellingSpecificGroupsDifferFromCanonicalTarget(t *testing.T) {
	join, ok := Lookup("ipv6-join-group")
	if !ok {
		t.Fatal("ipv6-join-group")
	}
	member, ok := Lookup("ip-add-membership")
	if !ok {
		t.Fatal("ip-add-membership")
	}
	if reflect.DeepEqual(join.Groups, member.Groups) {
		t.Fatalf("ipv6-join-group and ip-add-membership must keep distinct classic groups: %v", join.Groups)
	}
	if !reflect.DeepEqual(join.Groups, []string{"IP6"}) {
		t.Fatalf("ipv6-join-group groups=%v", join.Groups)
	}
	if !reflect.DeepEqual(member.Groups, []string{"IP4", "IP6"}) {
		t.Fatalf("ip-add-membership groups=%v", member.Groups)
	}
}

func TestCatalogGroupsMatchClassicOptionGroups(t *testing.T) {
	var missing, mismatch []string
	for spelling, e := range Options {
		want, ok := xio.ClassicOptionGroups[spelling]
		if !ok {
			missing = append(missing, spelling)
			continue
		}
		got := helpGroupsToInternal(e.Groups)
		if len(want) == 0 {
			// extract-classic-groups.py can miss GROUP_* after OPT_GROUP_*
			// tokens (gid-e, group-late, …). The -hhh catalog is authoritative.
			continue
		}
		if !sameStringSet(got, want) {
			mismatch = append(mismatch, spelling+": catalog="+strings.Join(got, ",")+" classicgroups="+strings.Join(want, ","))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("catalog spellings missing from ClassicOptionGroups: %s", strings.Join(missing, ", "))
	}
	if len(mismatch) > 0 {
		sort.Strings(mismatch)
		t.Errorf("help groups disagree with ClassicOptionGroups:\n  %s", strings.Join(mismatch, "\n  "))
	}
}

func testdataV(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "testdata", "tag-1.8.1.3.V"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAdvertisedCount(t *testing.T) {
	if AdvertisedCount != 795 {
		t.Fatalf("AdvertisedCount=%d, want 795", AdvertisedCount)
	}
	if len(Options) != AdvertisedCount {
		t.Fatalf("advertised catalog has %d spellings, want %d", len(Options), AdvertisedCount)
	}
}

func TestFeatureCompleteCanaries(t *testing.T) {
	advertised := []string{
		"openssl-certificate", "openssl-key", "openssl-cafile", "openssl-verify",
		"openssl-cipherlist", "cipherlist",
		"openssl-min-proto-version", "openssl-max-proto-version",
		"min-version", "max-version",
		"openssl-no-sni", "no-sni", "nosni",
		"history-file", "history", "noecho", "noprompt", "prompt",
		"tcpwrap", "tcpwrappers", "libwrap", "wrap",
		"tcpwrap-hosts-allow-table", "tcpwrap-hosts-deny-table",
	}
	for _, name := range advertised {
		if _, ok := Lookup(name); !ok {
			t.Errorf("missing advertised canary %q", name)
		}
	}
	e, ok := Lookup("b7200")
	if !ok {
		t.Fatal("b7200 must be in the advertised Linux -hhh catalog")
	}
	if e.Canonical != "b7200" || e.Phase != "FD" || e.Type != "CONST" || e.IsAlias() {
		t.Fatalf("b7200: canonical=%q phase=%q type=%q alias=%v", e.Canonical, e.Phase, e.Type, e.IsAlias())
	}
	if !reflect.DeepEqual(e.Groups, []string{"TERMIOS"}) {
		t.Fatalf("b7200 groups=%v", e.Groups)
	}
	if DocsOnlyNotInThisBinary["b7200"] != "" {
		t.Fatal("b7200 is advertised; remove it from DocsOnlyNotInThisBinary")
	}
}

func TestDocsOnlyNotInAdvertisedCatalog(t *testing.T) {
	for name := range DocsOnlyNotInThisBinary {
		if _, ok := Lookup(name); ok {
			t.Errorf("%q is advertised in the catalog; remove it from DocsOnlyNotInThisBinary", name)
		}
	}
	if DocsOnlyNotInThisBinary["udp-ignore-peerport"] == "" {
		t.Fatal("udp-ignore-peerport is documented and must be in DocsOnlyNotInThisBinary")
	}
}

func TestRequiredPublicSpellingsUnion(t *testing.T) {
	required := RequiredPublicSpellings()
	if _, ok := required["b7200"]; !ok {
		t.Fatal("RequiredPublicSpellings must include advertised b7200")
	}
	if _, ok := required["udp-ignore-peerport"]; !ok {
		t.Fatal("RequiredPublicSpellings must include documented udp-ignore-peerport")
	}
	if _, ok := required["method"]; !ok {
		t.Fatal("RequiredPublicSpellings must include documented method")
	}
	if _, ok := required["fips"]; !ok {
		t.Fatal("RequiredPublicSpellings must include documented fips")
	}
	if _, ok := required["openssl-method"]; ok {
		t.Fatal("openssl-method is a parser-only alias, not a documented public spelling")
	}
	if _, ok := required["openssl-fips"]; ok {
		t.Fatal("openssl-fips is a parser-only alias, not a documented public spelling")
	}
	if _, ok := required["cool-write"]; ok {
		t.Fatal("cool-write is an IntentionalPublicOmission")
	}
	if _, ok := required["coolwrite"]; ok {
		t.Fatal("coolwrite is an IntentionalPublicOmission")
	}
	want := 0
	for name := range Options {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		want++
	}
	for name := range DocsOnlyNotInThisBinary {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		if _, dup := Options[name]; dup {
			continue
		}
		want++
	}
	if got := len(required); got != want {
		t.Fatalf("RequiredPublicSpellings has %d names, want %d (Options ∪ DocsOnly, minus IntentionalPublicOmissions)", got, want)
	}
	for name := range Options {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		if _, ok := required[name]; !ok {
			t.Errorf("advertised %q missing from RequiredPublicSpellings", name)
		}
	}
	for name := range DocsOnlyNotInThisBinary {
		if _, ok := required[name]; !ok {
			t.Errorf("documented %q missing from RequiredPublicSpellings", name)
		}
	}
}

func TestIntentionalPublicOmissions(t *testing.T) {
	required := RequiredPublicSpellings()
	for name, reason := range IntentionalPublicOmissions {
		if reason == "" {
			t.Errorf("IntentionalPublicOmissions[%q] needs a reason", name)
		}
		if _, ok := required[name]; ok {
			t.Errorf("%q is an IntentionalPublicOmission; it must not be in RequiredPublicSpellings", name)
		}
	}
	if _, ok := Lookup("cool-write"); !ok {
		t.Fatal("classic advertises cool-write; keep it in Options")
	}
	if _, ok := Lookup("coolwrite"); !ok {
		t.Fatal("classic advertises coolwrite; keep it in Options")
	}
	if IntentionalPublicOmissions["cool-write"] == "" || IntentionalPublicOmissions["coolwrite"] == "" {
		t.Fatal("cool-write and coolwrite must be IntentionalPublicOmissions")
	}
}

func TestOptionalParserOnlyAliasesNotRequired(t *testing.T) {
	required := RequiredPublicSpellings()
	for name := range OptionalParserOnlyAliases {
		if _, ok := Lookup(name); ok {
			t.Errorf("%q is advertised; remove it from OptionalParserOnlyAliases", name)
		}
		if DocsOnlyNotInThisBinary[name] != "" {
			t.Errorf("%q is documented; it belongs in DocsOnlyNotInThisBinary, not OptionalParserOnlyAliases", name)
		}
		if _, ok := required[name]; ok {
			t.Errorf("%q is in RequiredPublicSpellings; optional parser-only aliases are not compatibility requirements", name)
		}
	}
	if _, ok := OptionalParserOnlyAliases["udp-ignore-peerport"]; ok {
		t.Fatal("udp-ignore-peerport is documented; it must not be in OptionalParserOnlyAliases")
	}
	if _, ok := OptionalParserOnlyAliases["b7200"]; ok {
		t.Fatal("b7200 is advertised; it must not be in OptionalParserOnlyAliases")
	}
	if OptionalParserOnlyAliases["openssl-method"] == "" || OptionalParserOnlyAliases["openssl-fips"] == "" {
		t.Fatal("openssl-method and openssl-fips are parser-only aliases")
	}
	if DocsOnlyNotInThisBinary["openssl-method"] != "" || DocsOnlyNotInThisBinary["openssl-fips"] != "" {
		t.Fatal("openssl-method and openssl-fips must not stay in DocsOnlyNotInThisBinary")
	}
}

func TestGoOnlyHelpAllowlistNotInClassicCatalog(t *testing.T) {
	for name := range GoOnlyHelpAllowlist {
		if _, ok := Lookup(name); ok {
			t.Errorf("%q is in the classic catalog; remove it from GoOnlyHelpAllowlist", name)
		}
	}
}

func TestCheckedInVRecordsFeatureCompleteDefines(t *testing.T) {
	v := testdataV(t)
	missing := MissingFeatureCompleteDefines(v)
	if len(missing) > 0 {
		t.Fatalf("testdata/tag-1.8.1.3.V missing #define %s", strings.Join(missing, ", "))
	}
	if strings.Contains(v, "socat version 1.8.1.3 on ") {
		t.Fatal("testdata/tag-1.8.1.3.V must sanitize the compile-date line")
	}
	if strings.Contains(v, "running on Linux version") {
		t.Fatal("testdata/tag-1.8.1.3.V must sanitize the kernel line")
	}
}

func TestOfficialBinaryHHHMatchesTestdata(t *testing.T) {
	bin, reason := findFeatureCompleteClassicBinary()
	if bin == "" {
		t.Skip(reason)
	}
	ver, err := exec.Command(bin, "-V").Output()
	if err != nil {
		t.Fatalf("%s -V: %v", bin, err)
	}
	if missing := MissingFeatureCompleteDefines(string(ver)); len(missing) > 0 {
		t.Skipf("%s -V is not feature-complete (missing #define %s)", bin, strings.Join(missing, ", "))
	}
	out, err := exec.Command(bin, "-hhh").Output()
	if err != nil {
		t.Fatalf("%s -hhh: %v", bin, err)
	}
	got, err := ParseHHHOptions(string(out))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseHHHOptions(testdataHHH(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["b7200"]; !ok {
		t.Skipf("%s -hhh is feature-complete but lacks b7200; this host's termios.h does not define B7200. The fixture is 795 spellings including b7200 (Ubuntu 26.04 / glibc #define B7200 7200U).", bin)
	}
	if len(got) != AdvertisedCount {
		t.Fatalf("%s -hhh has %d spellings, want %d", bin, len(got), AdvertisedCount)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s -hhh option catalog differs from testdata/tag-1.8.1.3.hhh", bin)
	}
}

func findFeatureCompleteClassicBinary() (string, string) {
	var candidates []string
	for _, key := range []string{"SOCAT", "CLASSIC_SOCAT"} {
		if v := os.Getenv(key); v != "" {
			candidates = append(candidates, v)
		}
	}
	var skipped []string
	for _, bin := range candidates {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		ver, err := exec.Command(bin, "-V").Output()
		if err != nil {
			skipped = append(skipped, bin+": -V failed")
			continue
		}
		if missing := MissingFeatureCompleteDefines(string(ver)); len(missing) > 0 {
			skipped = append(skipped, bin+": missing #define "+strings.Join(missing, ","))
			continue
		}
		return bin, ""
	}
	if len(skipped) == 0 {
		return "", "classic socat binary not available (set SOCAT or CLASSIC_SOCAT)"
	}
	return "", "no feature-complete classic socat binary (" + strings.Join(skipped, "; ") + ")"
}

func TestBuildClassicHelpCatalogScriptRefusesUserPath(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	script := filepath.Join(filepath.Dir(file), "../../scripts/build-classic-help-catalog.sh")
	cmd := exec.Command("bash", script)
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "SOCAT=") || strings.HasPrefix(e, "CLASSIC_SOCAT=") || strings.HasPrefix(e, "CLASSIC_BUILD_DIR=") {
			continue
		}
		env = append(env, e)
	}
	cmd.Env = append(env, "CLASSIC_BUILD_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for unsuitable CLASSIC_BUILD_DIR, output:\n%s", out)
	}
	if _, statErr := os.Stat(sentinel); statErr != nil {
		t.Fatalf("user CLASSIC_BUILD_DIR was deleted: %v\n%s", statErr, out)
	}
	if !bytes.Contains(out, []byte("Refusing to delete a user-controlled path")) {
		t.Fatalf("expected refuse-to-delete message, got:\n%s", out)
	}
}

func TestBuildClassicHelpCatalogScriptDoesNotForgeB7200(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../scripts/build-classic-help-catalog.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("env CPPFLAGS=-DB7200")) || bytes.Contains(b, []byte("./configure CPPFLAGS=-DB7200")) {
		t.Fatal("rebuild script must not force CPPFLAGS=-DB7200=7200U")
	}
	if !bytes.Contains(b, []byte("Do not pass CPPFLAGS=-DB7200=7200U")) {
		t.Fatal("rebuild script must fail with a prerequisite message instead of forging B7200")
	}
}

func helpGroupsToInternal(groups []string) []string {
	out := make([]string, 0, len(groups))
	seen := map[string]struct{}{}
	for _, g := range groups {
		if g == "(all)" {
			return nil
		}
		name := helpGroupToInternal[g]
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// helpGroupToInternal maps classic -hhh group names to ClassicOptionGroups tokens.
var helpGroupToInternal = map[string]string{
	"FD": "fd", "FIFO": "fifo", "CHR": "chr", "BLK": "blk", "REG": "reg",
	"SOCKET": "socket", "READLINE": "readline", "NAMED": "named", "OPEN": "open",
	"EXEC": "exec", "FORK": "fork", "LISTEN": "listen", "SHELL": "shell",
	"CHILD": "child", "RETRY": "retry", "TERMIOS": "termios", "RANGE": "range",
	"PTY": "pty", "PARENT": "parent", "UNIX": "sock-unix", "IP4": "sock-ip4",
	"IP6": "sock-ip6", "INTERFACE": "interface", "UDP": "ip-udp", "TCP": "ip-tcp",
	"SOCKS": "socks", "OPENSSL": "openssl", "PROCESS": "process", "APPL": "appl",
	"HTTP": "http", "POSIXMQ": "posixmq", "SCTP": "ip-sctp", "DCCP": "ip-dccp",
	"UDPLITE": "ip-udplite",
}
