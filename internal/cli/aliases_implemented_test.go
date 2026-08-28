package cli

import (
	"bytes"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
	"github.com/oittaa/socat/internal/parse"
)

// implementedAliasHelp is catalog spellings this PR advertises on an already
// implemented help row. Aliases appear in -hhh as "alias of <canonical>".
var implementedAliasHelp = []struct {
	alias, canonical string
}{
	{"o-rdonly", "rdonly"},
	{"o_rdonly", "rdonly"},
	{"o-wronly", "wronly"},
	{"o_wronly", "wronly"},
	{"o-rdwr", "rdwr"},
	{"o_rdwr", "rdwr"},
	{"o-creat", "creat"},
	{"o-create", "creat"},
	{"o_creat", "creat"},
	{"o_create", "creat"},
	{"o-excl", "excl"},
	{"o_excl", "excl"},
	{"o-trunc", "trunc"},
	{"ndelay", "nonblock"},
	{"o-ndelay", "nonblock"},
	{"o_ndelay", "nonblock"},
	{"f-setlk", "setlk"},
	{"setlk-wr", "setlk"},
	{"f-setlkw", "setlkw"},
	{"setlkw-wr", "setlkw"},
	{"lock", "setlkw"},
	{"lockw", "setlkw"},
	{"new", "unlink-early"},
	{"bytes", "readbytes"},
	{"crlf", "crnl"},
	{"cd", "chdir"},
	{"sid", "setsid"},
	{"login", "dash"},
	{"pgid", "setpgid"},
	{"close", "end-close"},
	{"maxchildren", "max-children"},
	{"intervall", "interval"},
	{"ipv6only", "ipv6-v6only"},
	{"v6only", "ipv6-v6only"},
	{"pty-intervall", "pty-interval"},
	{"termios-cfmakeraw", "cfmakeraw"},
	{"termios-rawer", "rawer"},
	{"crterase", "echoe"},
	{"crtkill", "echoke"},
	{"ctlecho", "echoctl"},
	{"hup", "hupcl"},
	{"tandem", "ixoff"},
	{"tun-no-pi", "iff-no-pi"},
	{"multicast", "iff-multicast"},
	{"notrailers", "iff-notrailers"},
	{"master", "iff-master"},
	{"slave", "iff-slave"},
	{"portsel", "iff-portsel"},
	{"automedia", "iff-automedia"},
	{"proxy-auth", "proxy-authorization"},
	{"resolv", "proxy-resolve"},
	{"certificate", "cert"},
	{"openssl-certificate", "cert"},
	{"openssl-key", "key"},
	{"openssl-cafile", "cafile"},
	{"openssl-verify", "verify"},
	{"cn", "commonname"},
	{"cipherlist", "ciphers"},
	{"min-proto-version", "openssl-min-proto-version"},
	{"max-proto-version", "openssl-max-proto-version"},
	{"no-sni", "nosni"},
	{"compress", "openssl-compress"},
	{"ext2-append", "fs-append"},
	{"ext3-append", "fs-append"},
	{"compr", "fs-compr"},
	{"nodump", "fs-nodump"},
	{"notail", "fs-notail"},
	{"journal", "fs-journal-data"},
	{"journal-data", "fs-journal-data"},
	{"ext2-sync", "fs-sync"},
	{"ioctl", "ioctl-void"},
	{"priority", "so-priority"},
	{"passcred", "so-passcred"},
	{"nocheck", "so-no-check"},
	{"no-check", "so-no-check"},
}

func TestImplementedAliasesHHHNotHH(t *testing.T) {
	var hh, hhh bytes.Buffer
	if err := printHelp(&hh, 2); err != nil {
		t.Fatal(err)
	}
	if err := printHelp(&hhh, 3); err != nil {
		t.Fatal(err)
	}
	hhText, hhhText := hh.String(), hhh.String()
	for _, tc := range implementedAliasHelp {
		if hideOpt(tc.canonical) || hideOptGroupForAlias(tc.canonical) {
			continue
		}
		if helpLineNames(hhText)[tc.alias] {
			t.Errorf("-hh lists alias %q; aliases belong in -hhh", tc.alias)
		}
		want := "alias of " + tc.canonical
		found := false
		for _, line := range strings.Split(hhhText, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == tc.alias && strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("-hhh missing %q as %s", tc.alias, want)
		}
	}
}

func TestRawHelpRemainsDistinctFromCFMakeRaw(t *testing.T) {
	if hideOpt("raw") || hideOptGroupForAlias("raw") {
		return
	}
	var hhh bytes.Buffer
	if err := printHelp(&hhh, 3); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(hhh.String(), "\n")
	foundRaw := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "raw" {
			continue
		}
		foundRaw = true
		if strings.Contains(line, "alias of") {
			t.Fatalf("raw must be a distinct classic operation, got help line %q", line)
		}
	}
	if !foundRaw {
		t.Fatal("-hhh missing distinct raw option")
	}
}

func helpLineNames(help string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out
}

func hideOptGroupForAlias(canonical string) bool {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name != canonical {
				continue
			}
			return hideOptGroup(group.title)
		}
	}
	return false
}

func TestCatalogAliasesOfAdvertisedCanonicalsAreAdvertised(t *testing.T) {
	advertised := advertisedHelpNames(true)
	var missing []string
	for spelling, e := range classiccatalog.Options {
		if _, ok := advertised[spelling]; ok {
			continue
		}
		if _, omit := classiccatalog.IntentionalPublicOmissions[spelling]; omit {
			continue
		}
		if class, _ := classiccatalog.ClassifyOption(spelling, runtime.GOOS); class == classiccatalog.ClassUnsupported {
			continue
		}
		goCanon := parse.CanonicalOptionName(spelling)
		if goCanon == spelling {
			goCanon = parse.CanonicalOptionName(e.Canonical)
		}
		if goCanon == spelling {
			continue
		}
		if _, ok := advertised[goCanon]; !ok {
			continue
		}
		missing = append(missing, spelling+"->"+goCanon)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("catalog aliases of advertised implemented options missing from Go -hhh (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba): %s",
			strings.Join(missing, ", "))
	}
}

func TestImplementedAliasesRejectedWithCanonicalGroups(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr string
	}{
		{spec: "CREATE:file,o-excl", wantErr: "not supported"},
		{spec: "CREATE:file,o-creat", wantErr: "not supported"},
		{spec: "OPEN:file,o-excl"},
		{spec: "OPEN:file,o-creat"},
		{spec: "OPEN:file,o-rdonly"},
		{spec: "OPEN:file,o-rdwr"},
		{spec: "OPEN:file,lock"},
		{spec: "TCP:localhost:1,bytes=4"},
		{spec: "TCP:localhost:1,crlf"},
		{spec: "TCP:localhost:1,close"},
		{spec: "TCP:localhost:1,o-excl", wantErr: "not supported"},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			spec    string
			wantErr string
		}{spec: "OPEN:file,ndelay"})
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			ch, err := parse.ParseChannel(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = validateChannelOptions(ch)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want %q", err, tc.wantErr)
			}
		})
	}
}
