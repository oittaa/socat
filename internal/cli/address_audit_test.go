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

func registeredAddressNames() map[string]bool {
	out := map[string]bool{}
	for _, r := range xio.AddressRegistrations() {
		out[r.Name] = true
	}
	return out
}

func addressEnabled(name string) bool {
	reg, ok := xio.AddressRegistrationForType(name)
	return ok && reg.Enabled
}

func addressParityProblems(goos string, registered map[string]bool) []string {
	var problems []string
	for name := range xio.ClassicAddressGroups {
		class, reason := classiccatalog.ClassifyAddress(name, goos)
		switch class {
		case classiccatalog.AddrParserShorthand:
			continue
		case classiccatalog.AddrUnsupportedFamily:
			if registered[name] {
				problems = append(problems, fmt.Sprintf("unsupported address %q is registered (%s)", name, reason))
			}
			continue
		case classiccatalog.AddrExpectedMissingCanonical:
			if registered[name] {
				problems = append(problems, fmt.Sprintf("implemented canonical address %q remains in the missing manifest (%s)", name, reason))
			}
			continue
		case classiccatalog.AddrExpectedMissingAlias:
			if registered[name] {
				problems = append(problems, fmt.Sprintf("implemented address alias %q remains in the missing manifest (%s)", name, reason))
			}
			canon := classiccatalog.ExpectedMissingAddressAliases[name]
			if !registered[canon] {
				problems = append(problems, fmt.Sprintf("supported alias %q listed but canonical %q is not registered", name, canon))
			}
			continue
		case classiccatalog.AddrForeign:
			if addressEnabled(name) {
				problems = append(problems, fmt.Sprintf("foreign-on-%s address %q is enabled (%s)", goos, name, reason))
			}
			continue
		case classiccatalog.AddrMustRegister:
			if alias, ok := xio.ClassicAddressAliases[name]; ok && alias != name {
				if _, unsup := classiccatalog.UnsupportedAddressNames[alias]; unsup {
					problems = append(problems, fmt.Sprintf("alias %q of unsupported %q is not classified as unsupported", name, alias))
					continue
				}
				if _, missing := classiccatalog.ExpectedMissingCanonicalAddresses[alias]; missing {
					if registered[name] {
						problems = append(problems, fmt.Sprintf("alias %q of unimplemented %q is registered", name, alias))
					}
					continue
				}
				if registered[name] {
					continue
				}
				if registered[alias] {
					problems = append(problems, fmt.Sprintf("new missing alias %q of implemented %q", name, alias))
					continue
				}
				problems = append(problems, fmt.Sprintf("missing alias %q and canonical %q", name, alias))
				continue
			}
			if registered[name] {
				continue
			}
			problems = append(problems, fmt.Sprintf("implemented canonical address %q disappeared or is a new unclassified gap", name))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestClassicAddressNameAudit(t *testing.T) {
	if err := classiccatalog.ValidateParityManifests(); err != nil {
		t.Fatal(err)
	}
	registered := registeredAddressNames()
	if problems := addressParityProblems(runtime.GOOS, registered); len(problems) > 0 {
		t.Fatalf("address parity audit failed:\n  %s", strings.Join(problems, "\n  "))
	}

	for alias, canon := range classiccatalog.ExpectedMissingAddressAliases {
		classicCanon, ok := xio.ClassicAddressAliases[alias]
		if !ok {
			t.Errorf("supported missing alias %q is not in ClassicAddressAliases", alias)
			continue
		}
		if classicCanon != canon {
			t.Errorf("supported missing alias %q: catalog canonical %q, classic %q", alias, canon, classicCanon)
		}
		if !registered[canon] {
			t.Errorf("supported missing alias %q: canonical %q is not registered", alias, canon)
		}
		if registered[alias] {
			t.Errorf("supported missing alias %q is already registered; remove it from ExpectedMissingAddressAliases", alias)
		}
		if _, ok := classiccatalog.UnsupportedAddressNames[alias]; ok {
			t.Errorf("supported missing alias %q is listed as an unsupported family", alias)
		}
		if _, ok := classiccatalog.ExpectedMissingCanonicalAddresses[canon]; ok {
			t.Errorf("supported missing alias %q points at unimplemented %q", alias, canon)
		}
	}

	for name := range classiccatalog.UnsupportedAddressNames {
		if _, ok := xio.ClassicAddressGroups[name]; !ok {
			t.Errorf("unsupported address %q is not in ClassicAddressGroups", name)
		}
		if registered[name] {
			t.Errorf("unsupported address %q is registered", name)
		}
	}
	for name := range classiccatalog.ExpectedMissingCanonicalAddresses {
		if _, ok := xio.ClassicAddressGroups[name]; !ok {
			t.Errorf("expected-missing canonical %q is not in ClassicAddressGroups", name)
		}
		if _, ok := xio.ClassicAddressAliases[name]; ok {
			t.Errorf("expected-missing canonical %q is a classic alias key; list it as an alias", name)
		}
	}

	if _, ok := xio.AddressRegistrationForType("STDIO"); !ok {
		t.Fatal("STDIO opener missing")
	}
}

func TestAddressParityFailsIfImplementedAliasDisappears(t *testing.T) {
	registered := registeredAddressNames()
	const name = "TCP-L"
	if !registered[name] {
		t.Fatalf("%q is not registered", name)
	}
	delete(registered, name)
	problems := addressParityProblems(runtime.GOOS, registered)
	if len(problems) == 0 {
		t.Fatal("expected audit failure after removing an implemented address alias")
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

func TestAddressParityFailsIfImplementedAliasStaysInMissingManifest(t *testing.T) {
	registered := registeredAddressNames()
	const name = "ABSTRACT"
	if _, ok := classiccatalog.ExpectedMissingAddressAliases[name]; !ok {
		t.Fatalf("%q is not in the supported-alias backlog", name)
	}
	registered[name] = true
	problems := addressParityProblems(runtime.GOOS, registered)
	if len(problems) == 0 {
		t.Fatal("expected audit failure when a missing alias is registered")
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, name) && strings.Contains(p, "missing manifest") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit problems do not mention stale alias %q: %s", name, strings.Join(problems, "; "))
	}
}
