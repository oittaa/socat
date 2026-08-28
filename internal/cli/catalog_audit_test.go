package cli

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
	"github.com/oittaa/socat/internal/xio"
)

func advertisedHelpNames(all bool) map[string]struct{} {
	out := map[string]struct{}{}
	for _, group := range helpOptionGroups() {
		if hideOptGroup(group.title) {
			continue
		}
		for _, option := range group.opts {
			if hideOpt(option.name) {
				continue
			}
			out[option.name] = struct{}{}
			if all {
				for _, alias := range option.aliases {
					out[alias] = struct{}{}
				}
			}
		}
	}
	for _, name := range extraHelpNames(all) {
		out[name] = struct{}{}
	}
	return out
}

func helpTableContains(name string) bool {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name == name {
				return true
			}
			for _, alias := range option.aliases {
				if alias == name {
					return true
				}
			}
		}
	}
	for _, extra := range xio.TermiosHelpNames() {
		if extra == name {
			return true
		}
	}
	return false
}

func optionHiddenOnThisPlatform(name string) bool {
	for _, group := range helpOptionGroups() {
		groupHidden := hideOptGroup(group.title)
		for _, option := range group.opts {
			match := option.name == name
			if !match {
				for _, alias := range option.aliases {
					if alias == name {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
			return groupHidden || hideOpt(option.name)
		}
	}
	if e, ok := classiccatalog.Lookup(name); ok {
		for _, group := range e.Groups {
			switch group {
			case "TERMIOS", "PTY":
				if hideOptGroup("PTY and TERMIOS") {
					return true
				}
				if group == "TERMIOS" && !termiosHelpHas(name) && !helpTableContains(name) {
					// Bauds and flags the host <termios.h> does not define.
					return true
				}
			case "POSIXMQ":
				if hideOptGroup("POSIX message queues") {
					return true
				}
			case "INTERFACE":
				if hideOptGroup("TUN and INTERFACE") {
					return true
				}
			}
		}
	}
	return false
}

func termiosHelpHas(name string) bool {
	for _, extra := range xio.TermiosHelpNames() {
		if extra == name {
			return true
		}
	}
	return false
}

func optionParityProblems(goos string, advertised map[string]struct{}) []string {
	names := map[string]struct{}{}
	for name := range classiccatalog.RequiredPublicSpellings() {
		names[name] = struct{}{}
	}
	for name := range classiccatalog.UnsupportedPublic() {
		names[name] = struct{}{}
	}
	for name := range classiccatalog.ExpectedMissingAll() {
		names[name] = struct{}{}
	}
	for name := range classiccatalog.ForeignPublic() {
		names[name] = struct{}{}
	}

	var problems []string
	for name := range names {
		class, reason := classiccatalog.ClassifyOption(name, goos)
		_, listed := advertised[name]
		switch class {
		case classiccatalog.ClassOptionalParserOnly:
			if listed {
				problems = append(problems, fmt.Sprintf("parser-only alias %q is advertised", name))
			}
		case classiccatalog.ClassUnsupported:
			if listed {
				problems = append(problems, fmt.Sprintf("unsupported %q is advertised (%s)", name, reason))
			}
		case classiccatalog.ClassForeign:
			if listed {
				problems = append(problems, fmt.Sprintf("foreign-on-%s %q is advertised (%s)", goos, name, reason))
			}
		case classiccatalog.ClassExpectedMissing:
			if listed {
				problems = append(problems, fmt.Sprintf("implemented %q remains in the expected-missing manifest (%s)", name, reason))
			}
		case classiccatalog.ClassMustAdvertise:
			if listed {
				break
			}
			if optionHiddenOnThisPlatform(name) {
				break
			}
			if helpTableContains(name) {
				problems = append(problems, fmt.Sprintf("implemented public spelling %q disappeared from %s -hhh", name, goos))
			} else {
				problems = append(problems, fmt.Sprintf("unclassified missing public spelling %q on %s", name, goos))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func TestCatalogVsGoHelp(t *testing.T) {
	if err := classiccatalog.ValidateParityManifests(); err != nil {
		t.Fatal(err)
	}

	advertised := advertisedHelpNames(true)
	var extra []string
	for name := range advertised {
		if _, ok := classiccatalog.Lookup(name); ok {
			continue
		}
		if _, ok := classiccatalog.GoOnlyHelpAllowlist[name]; ok {
			continue
		}
		extra = append(extra, name)
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Fatalf("Go -hhh advertises names not in the classic catalog and not on GoOnlyHelpAllowlist: %s",
			strings.Join(extra, ", "))
	}

	var stale, unadvertised []string
	for name := range classiccatalog.GoOnlyHelpAllowlist {
		if _, ok := classiccatalog.Lookup(name); ok {
			stale = append(stale, name)
		}
		if _, ok := advertised[name]; !ok {
			if optionHiddenOnThisPlatform(name) {
				continue
			}
			unadvertised = append(unadvertised, name)
		}
	}
	sort.Strings(stale)
	sort.Strings(unadvertised)
	if len(stale) > 0 {
		t.Errorf("GoOnlyHelpAllowlist names that are in the classic catalog: %s", strings.Join(stale, ", "))
	}
	if runtime.GOOS == "linux" && len(unadvertised) > 0 {
		t.Errorf("GoOnlyHelpAllowlist names not advertised in this build's -hhh: %s", strings.Join(unadvertised, ", "))
	}

	if problems := optionParityProblems(runtime.GOOS, advertised); len(problems) > 0 {
		t.Fatalf("option parity audit failed:\n  %s", strings.Join(problems, "\n  "))
	}

	class, _ := classiccatalog.ClassifyOption("udp-ignore-peerport", runtime.GOOS)
	if class != classiccatalog.ClassUnsupported {
		t.Fatalf("udp-ignore-peerport class=%s; documented by classic man page but never implemented in C", class)
	}
	if _, ok := advertised["udp-ignore-peerport"]; ok {
		t.Fatal("udp-ignore-peerport must not be advertised; classic rejects it as unknown")
	}
	if _, ok := classiccatalog.RequiredPublicSpellings()["udp-ignore-peerport"]; !ok {
		t.Fatal("RequiredPublicSpellings must include documented udp-ignore-peerport")
	}
	if _, ok := classiccatalog.ImplementationBacklog(runtime.GOOS)["udp-ignore-peerport"]; ok {
		t.Fatal("udp-ignore-peerport must not be in the implementation backlog; classic C never implemented it")
	}
	if _, ok := classiccatalog.UnsupportedPublic()["udp-ignore-peerport"]; !ok {
		t.Fatal("udp-ignore-peerport must be classified unsupported")
	}

	for name := range classiccatalog.OptionalParserOnlyAliases {
		if _, ok := advertised[name]; ok {
			t.Errorf("Go -hhh must not advertise parser-only alias %q", name)
		}
	}
	for name := range classiccatalog.UnsupportedPublic() {
		if _, ok := advertised[name]; ok {
			t.Errorf("Go -hhh must not advertise unsupported %q", name)
		}
		if _, ok := classiccatalog.ImplementationBacklog(runtime.GOOS)[name]; ok {
			t.Errorf("unsupported %q must not be in the implementation backlog", name)
		}
	}
	for _, name := range []string{
		"method", "fips", "openssl-method", "openssl-fips",
		"openssl-egd", "egd", "openssl-pseudo", "pseudo",
		"openssl-dhparam", "dhparam", "dh", "dhparams",
		"openssl-maxfraglen", "maxfraglen",
		"openssl-maxsendfrag", "maxsendfrag",
	} {
		if _, ok := advertised[name]; ok {
			t.Errorf("Go -hhh must not advertise unsupported OpenSSL option %q as honored", name)
		}
		if _, ok := classiccatalog.ImplementationBacklog(runtime.GOOS)[name]; ok {
			t.Errorf("OpenSSL exclusion %q must not be in the implementation backlog", name)
		}
	}
}

func TestParityFailsIfImplementedOptionDisappears(t *testing.T) {
	advertised := advertisedHelpNames(true)
	const name = "retry"
	if _, ok := advertised[name]; !ok {
		t.Fatalf("%q is not advertised on %s; pick another implemented name", name, runtime.GOOS)
	}
	delete(advertised, name)
	problems := optionParityProblems(runtime.GOOS, advertised)
	if len(problems) == 0 {
		t.Fatal("expected audit failure after removing an implemented option")
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, name) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit problems do not mention %q: %s", name, strings.Join(problems, "; "))
	}
}

func TestParityFailsIfImplementedOptionStaysInMissingManifest(t *testing.T) {
	advertised := advertisedHelpNames(true)
	const name = "ai-all"
	class, _ := classiccatalog.ClassifyOption(name, runtime.GOOS)
	if class != classiccatalog.ClassExpectedMissing {
		t.Fatalf("%q class=%s on %s; want expected-missing", name, class, runtime.GOOS)
	}
	advertised[name] = struct{}{}
	problems := optionParityProblems(runtime.GOOS, advertised)
	if len(problems) == 0 {
		t.Fatal("expected audit failure when an expected-missing option is advertised")
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, name) && strings.Contains(p, "expected-missing") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit problems do not mention stale missing %q: %s", name, strings.Join(problems, "; "))
	}
}
