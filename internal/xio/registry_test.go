package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func helpKeyword(syntax string) string {
	if i := strings.IndexAny(syntax, ":["); i >= 0 {
		return strings.ToUpper(syntax[:i])
	}
	return strings.ToUpper(syntax)
}

func TestOpenersHaveHelpOrAreDisabled(t *testing.T) {
	regs := xio.AddressRegistrations()
	if len(regs) == 0 {
		t.Fatal("no addresses registered; import of xio/all failed")
	}

	help := map[string]bool{}
	var titles []string
	for _, g := range xio.HelpAddressGroups() {
		titles = append(titles, g.Title)
		for _, a := range g.Addrs {
			help[helpKeyword(a.Syntax)] = true
		}
	}

	for _, r := range regs {
		if r.Syntax == "" {
			t.Errorf("opener %s has no help Syntax", r.Name)
			continue
		}
		if helpKeyword(r.Syntax) != r.Name {
			t.Errorf("opener %s help syntax %q does not start with that name", r.Name, r.Syntax)
		}
		if r.Enabled && !help[r.Name] {
			t.Errorf("opener %s is enabled but missing from -h", r.Name)
		}
		if !r.Enabled && help[r.Name] {
			t.Errorf("opener %s is disabled but still listed in -h", r.Name)
		}
	}

	order := xio.DefaultHelpGroupOrder()
	idx := 0
	for _, title := range titles {
		found := -1
		for i := idx; i < len(order); i++ {
			if order[i] == title {
				found = i
				break
			}
		}
		if found < 0 {
			t.Errorf("help group %q is not in DefaultHelpGroupOrder or is out of order", title)
			continue
		}
		idx = found + 1
	}
}

func TestRegisteredAddressOptionCaps(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{name: "UDP-LISTEN", want: []string{xio.OptCapListen, xio.OptCapIPFilter, xio.OptCapPort, xio.OptCapLowport}},
		{name: "UDP-RECVFROM", want: []string{xio.OptCapIPFilter, xio.OptCapPort, xio.OptCapLowport}},
		{name: "UNIX-RECVFROM", want: nil},
		{name: "UNIX-LISTEN", want: []string{xio.OptCapListen}},
		{name: "TCP-LISTEN", want: []string{xio.OptCapListen, xio.OptCapIPFilter, xio.OptCapPort, xio.OptCapLowport}},
		{name: "SOCKET-LISTEN", want: []string{xio.OptCapListen}},
		{name: "OPEN", want: []string{xio.OptCapOpen}},
		{name: "CREATE", want: nil},
	}
	for _, tc := range cases {
		reg, ok := xio.AddressRegistrationForType(tc.name)
		if !ok {
			t.Errorf("%s: not registered", tc.name)
			continue
		}
		if len(reg.OptionCaps) != len(tc.want) {
			t.Errorf("%s OptionCaps=%v want %v", tc.name, reg.OptionCaps, tc.want)
			continue
		}
		for i, cap := range tc.want {
			if reg.OptionCaps[i] != cap {
				t.Errorf("%s OptionCaps=%v want %v", tc.name, reg.OptionCaps, tc.want)
				break
			}
		}
	}
}
