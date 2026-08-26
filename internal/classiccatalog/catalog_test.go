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
		t.Fatal("generated output differs from checked-in catalog_gen.go; regenerate from testdata/tag-1.8.1.3.hhh")
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

func TestOfficialBinaryHHHMatchesTestdata(t *testing.T) {
	bin := os.Getenv("SOCAT")
	if bin == "" {
		const fallback = "/tmp/socat-1.8.1.3/socat"
		if _, err := os.Stat(fallback); err == nil {
			bin = fallback
		}
	}
	if bin == "" {
		t.Skip("classic socat binary not available")
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s -hhh option catalog differs from testdata/tag-1.8.1.3.hhh", bin)
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
