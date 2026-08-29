package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	_ "github.com/oittaa/socat/internal/xio/all"
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

func TestHelpListsResNSAddrAndAliases(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	if !strings.Contains(help, "    res-nsaddr ") {
		t.Fatal("-hhh missing res-nsaddr")
	}
	for _, alias := range []string{"dns", "nameserver", "nsaddr"} {
		found := false
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == alias && strings.Contains(line, "alias of res-nsaddr") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("-hhh missing %q as alias of res-nsaddr", alias)
		}
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
	if runtime.GOOS != "windows" {
		canonical = append(canonical, "user", "group", "ioctl-void")
		aliases["uid"] = "user"
		aliases["owner"] = "user"
		aliases["gid"] = "group"
		aliases["ioctl"] = "ioctl-void"
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
		"openssl-compress", "openssl-min-proto-version", "openssl-max-proto-version",
	}
	aliases := map[string]string{
		"certificate":         "cert",
		"openssl-certificate": "cert",
		"openssl-key":         "key",
		"openssl-cafile":      "cafile",
		"openssl-verify":      "verify",
		"cn":                  "commonname",
		"cipherlist":          "ciphers",
		"compress":            "openssl-compress",
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

func TestHelpDoesNotAdvertiseDCCP(t *testing.T) {
	var version bytes.Buffer
	if err := printVersion(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(version.String(), "#undef WITH_DCCP") {
		t.Fatalf("missing #undef WITH_DCCP:\n%s", version.String())
	}
	for _, level := range []int{1, 2, 3} {
		var output bytes.Buffer
		if err := printHelp(&output, level); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(output.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			upper := strings.ToUpper(name)
			if strings.HasPrefix(upper, "DCCP") || name == "ccid" || name == "dccp-set-ccid" {
				t.Errorf("-h%s advertises DCCP spelling %q: %s", strings.Repeat("h", level-1), name, strings.TrimSpace(line))
			}
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

func TestHideDarwinOnlyIPRecv(t *testing.T) {
	names := []string{"ip-recvdstaddr", "ip-recvif", "recvdstaddr", "iprecvdstaddr", "recvif"}
	for _, name := range names {
		if hideDarwinOnlyIPRecv(name, "darwin") {
			t.Errorf("%q hidden on darwin", name)
		}
		for _, goos := range []string{"linux", "windows", "freebsd", "openbsd", "netbsd", "dragonfly", "aix", "solaris"} {
			if !hideDarwinOnlyIPRecv(name, goos) {
				t.Errorf("%q not hidden on %s", name, goos)
			}
		}
	}
	if hideDarwinOnlyIPRecv("nopush", "freebsd") {
		t.Fatal("nopush is not a Darwin-only IP recv option")
	}
	if hideDarwinOnlyIPRecv("so-timestamp", "linux") {
		t.Fatal("so-timestamp is not Darwin-only")
	}
}

func TestHideLinuxOnlyRemainingIPv4(t *testing.T) {
	names := []string{
		"ip-retopts", "retopts", "ipretopts",
		"ip-router-alert", "iprouteralert", "routeralert",
	}
	for _, name := range names {
		if hideLinuxOnlyRemainingIPv4(name, "linux") {
			t.Errorf("%q hidden on linux", name)
		}
		for _, goos := range []string{"darwin", "windows", "freebsd", "openbsd", "netbsd"} {
			if !hideLinuxOnlyRemainingIPv4(name, goos) {
				t.Errorf("%q not hidden on %s", name, goos)
			}
		}
	}
	if hideLinuxOnlyRemainingIPv4("ip-recvopts", "darwin") {
		t.Fatal("ip-recvopts is not a Linux-only remaining IPv4 option")
	}
}
