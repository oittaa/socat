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

func TestHelpOmitsDCCP(t *testing.T) {
	for _, g := range xio.HelpAddressGroups() {
		for _, a := range g.Addrs {
			if kw := helpKeyword(a.Syntax); strings.HasPrefix(kw, "DCCP") {
				t.Errorf("help lists DCCP type %q", a.Syntax)
			}
			for _, al := range a.Aliases {
				if strings.HasPrefix(strings.ToUpper(al), "DCCP") {
					t.Errorf("help lists DCCP alias %q", al)
				}
			}
		}
	}
}

func TestUDPDatagramHelpDescribesUnconnected(t *testing.T) {
	for _, g := range xio.HelpAddressGroups() {
		for _, a := range g.Addrs {
			if helpKeyword(a.Syntax) != "UDP-DATAGRAM" {
				continue
			}
			if strings.Contains(a.Desc, "connected") && !strings.Contains(a.Desc, "unconnected") {
				t.Fatalf("UDP-DATAGRAM help %q still describes a connected socket", a.Desc)
			}
			if !strings.Contains(a.Desc, "unconnected") {
				t.Fatalf("UDP-DATAGRAM help %q should say unconnected", a.Desc)
			}
			return
		}
	}
	t.Fatal("UDP-DATAGRAM missing from help")
}

func TestRegisteredAddressesHaveOptionCaps(t *testing.T) {
	for _, reg := range xio.AddressRegistrations() {
		if len(reg.OptionCaps) == 0 {
			t.Errorf("%s has empty OptionCaps", reg.Name)
		}
	}
}
