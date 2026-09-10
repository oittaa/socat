package cli

import (
	"bytes"
	"regexp"
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

// helpInternalTerm matches catalog/internal tokens that must not appear in
// -h/-hh/-hhh. type= is matched without a preceding identifier so socktype=
// in UNIX address descriptions is allowed.
var helpInternalTerm = regexp.MustCompile(`(?i)\bclassic\b|groups=|(?:^|[^A-Za-z0-9-])type=|phase=|\bPH_[A-Z0-9]+|\bTYPE_[A-Z0-9]+|\bGROUP_[A-Z0-9]+|\bOFUNC_[A-Z0-9]+`)

func TestHelpOmitsInternalMetadata(t *testing.T) {
	for _, level := range []int{1, 2, 3} {
		var output bytes.Buffer
		if err := printHelp(&output, level); err != nil {
			t.Fatal(err)
		}
		flag := "-h" + strings.Repeat("h", level-1)
		for i, line := range strings.Split(output.String(), "\n") {
			if loc := helpInternalTerm.FindStringIndex(line); loc != nil {
				t.Errorf("%s line %d contains %q: %s", flag, i+1, line[loc[0]:loc[1]], strings.TrimSpace(line))
			}
		}
	}
}

// helpOptionFlagListed reports whether an Options: line advertises token as
// fields[0]. Substring search is wrong for "-D": UDP-DATAGRAM contains it.
func helpOptionFlagListed(help, token string) bool {
	for _, line := range strings.Split(help, "\n") {
		if !strings.HasPrefix(line, "  -") || strings.HasPrefix(line, "    ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == token {
			return true
		}
	}
	return false
}

func TestHelpOptionFlagListedIgnoresDatagramSubstring(t *testing.T) {
	help := "Options:\n  -ls             log to stderr\n\nAddress types:\n    UDP-DATAGRAM:<addr>  datagram\n"
	if helpOptionFlagListed(help, "-D") {
		t.Fatal("UDP-DATAGRAM must not count as the -D option")
	}
	if !helpOptionFlagListed(help+"  -D              analyze file descriptors before transfer\n", "-D") {
		t.Fatal("missing -D option line")
	}
}

func TestHelpWaitlockPollInterval(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 2); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	if strings.Contains(help, "100ms") {
		t.Fatal("waitlock help still mentions a 100ms CLI -W interval")
	}
	if !strings.Contains(help, "1s poll") {
		t.Fatal("waitlock help missing 1s poll")
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

func TestHideLinuxOnlyIPv6RecvExt(t *testing.T) {
	names := []string{"ipv6-recvdstopts", "recvdstopts", "ipv6-recvhopopts", "recvhopopts"}
	for _, name := range names {
		if hideLinuxOnlyIPv6RecvExt(name, "linux") {
			t.Errorf("%q hidden on linux", name)
		}
		for _, goos := range []string{"darwin", "windows"} {
			if !hideLinuxOnlyIPv6RecvExt(name, goos) {
				t.Errorf("%q not hidden on %s", name, goos)
			}
		}
	}
	if hideLinuxOnlyIPv6RecvExt("ipv6-recvrthdr", "darwin") {
		t.Fatal("ipv6-recvrthdr is advertised on Darwin")
	}
}

func TestHideLinuxOnlyRecvErr(t *testing.T) {
	names := []string{"ip-recverr", "recverr", "iprecverr"}
	for _, name := range names {
		if hideLinuxOnlyRecvErr(name, "linux") {
			t.Errorf("%q hidden on linux", name)
		}
		for _, goos := range []string{"darwin", "windows"} {
			if !hideLinuxOnlyRecvErr(name, goos) {
				t.Errorf("%q not hidden on %s", name, goos)
			}
		}
	}
	if hideLinuxOnlyRecvErr("ipv6-recverr", "linux") {
		t.Fatal("ipv6-recverr is rejected, not a hidden Linux-only advertised option")
	}
}
