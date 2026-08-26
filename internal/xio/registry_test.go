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
		must []string
		not  []string
	}{
		{name: "UDP-LISTEN", must: []string{"listen", "range", "ip-udp", "child"}, not: []string{"termios", "pty", "open"}},
		{name: "UDP-RECVFROM", must: []string{"range", "ip-udp", "child"}, not: []string{"listen"}},
		{name: "UNIX-RECVFROM", must: []string{"sock-unix", "child"}, not: []string{"listen", "range"}},
		{name: "UNIX-LISTEN", must: []string{"listen", "sock-unix", "child"}, not: []string{"range"}},
		{name: "TCP-LISTEN", must: []string{"listen", "range", "ip-tcp", "child"}, not: []string{"pty"}},
		{name: "SOCKET-LISTEN", must: []string{"listen", "range", "child"}},
		{name: "OPEN", must: []string{"open", "named"}, not: []string{"listen", "socket"}},
		{name: "CREATE", must: []string{"named", "reg"}, not: []string{"open"}},
		{name: "TLS-LISTEN", must: []string{"listen", "openssl", "ip-tcp"}},
		{name: "QUIC", must: []string{"openssl", "ip-udp"}},
		{name: "WS", must: []string{"ip-tcp", "socket"}},
		{name: "VSOCK-CONNECT", must: []string{"socket", "child", "retry"}, not: []string{"listen", "range", "ip-tcp"}},
		{name: "VSOCK-LISTEN", must: []string{"listen", "socket", "child", "retry"}, not: []string{"range", "ip-tcp"}},
	}
	for _, tc := range cases {
		reg, ok := xio.AddressRegistrationForType(tc.name)
		if !ok {
			t.Errorf("%s: not registered", tc.name)
			continue
		}
		have := map[string]bool{}
		for _, c := range reg.OptionCaps {
			have[c] = true
		}
		for _, cap := range tc.must {
			if !have[cap] {
				t.Errorf("%s missing cap %q: %v", tc.name, cap, reg.OptionCaps)
			}
		}
		for _, cap := range tc.not {
			if have[cap] {
				t.Errorf("%s unexpected cap %q: %v", tc.name, cap, reg.OptionCaps)
			}
		}
	}
}

func TestRegisteredAddressesCarryClassicGroups(t *testing.T) {
	for _, reg := range xio.AddressRegistrations() {
		classic := xio.ClassicAddressCaps(reg.Name)
		if len(classic) == 0 {
			continue
		}
		have := map[string]bool{}
		for _, c := range reg.OptionCaps {
			have[c] = true
		}
		for _, g := range classic {
			if !have[g] {
				t.Errorf("%s missing classic group %q; OptionCaps=%v", reg.Name, g, reg.OptionCaps)
			}
		}
	}
}
