package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func helpFieldNames(help string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(help, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = append(out[fields[0]], strings.TrimSpace(line))
	}
	return out
}

func TestClassicAddressAliasesHHHNotH(t *testing.T) {
	var h, hhh bytes.Buffer
	if err := printHelp(&h, 1); err != nil {
		t.Fatal(err)
	}
	if err := printHelp(&hhh, 3); err != nil {
		t.Fatal(err)
	}
	hNames := helpFieldNames(h.String())
	hhhNames := helpFieldNames(hhh.String())

	direct := map[string]bool{}
	for _, r := range xio.AddressRegistrations() {
		direct[r.Name] = true
	}

	seen := map[string]int{}
	for alias, dest := range xio.ClassicAddressAliases {
		if alias == "-" || alias == dest || direct[alias] {
			continue
		}
		reg, ok := xio.AddressRegistrationForType(alias)
		if !ok {
			if lines := hNames[alias]; len(lines) > 0 {
				t.Errorf("-h lists unknown alias %q: %s", alias, strings.Join(lines, "; "))
			}
			if lines := hhhNames[alias]; len(lines) > 0 {
				t.Errorf("-hhh lists unknown alias %q: %s", alias, strings.Join(lines, "; "))
			}
			continue
		}
		if lines := hNames[alias]; len(lines) > 0 {
			t.Errorf("-h must not present %q as an independent type: %s", alias, strings.Join(lines, "; "))
		}
		if !reg.Enabled {
			if lines := hhhNames[alias]; len(lines) > 0 {
				t.Errorf("-hhh lists disabled alias %q: %s", alias, strings.Join(lines, "; "))
			}
			continue
		}
		want := "alias of " + dest
		lines := hhhNames[alias]
		if len(lines) != 1 {
			t.Errorf("-hhh alias %q lines=%d want 1: %s", alias, len(lines), strings.Join(lines, "; "))
			continue
		}
		if !strings.Contains(lines[0], want) {
			t.Errorf("-hhh %q line %q want %s", alias, lines[0], want)
		}
		seen[alias]++
	}
	for alias, n := range seen {
		if n != 1 {
			t.Errorf("alias %q counted %d times", alias, n)
		}
	}
}

func TestTCPLStaysDirectHelpRow(t *testing.T) {
	var h bytes.Buffer
	if err := printHelp(&h, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.String(), "TCP-L:") {
		t.Fatal("-h missing directly registered TCP-L syntax")
	}
}
