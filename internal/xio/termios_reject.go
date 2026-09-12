package xio

import (
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
)

// RejectUnsupportedTermios fails when a spec requests a termios option on a
// platform that does not implement termios (Windows). Same shape as
// RejectUnsupportedIPAncillary: do not accept the option as a silent no-op.
func RejectUnsupportedTermios(s addrconfig.Address) error {
	if FeatureTERMIOS {
		return nil
	}
	if len(s.Terminal.Actions) == 0 {
		return nil
	}
	name := s.Terminal.Actions[0].Name
	if name == "" {
		name = "termios"
	}
	typ := s.Type
	if typ == "" {
		typ = "address"
	}
	return fmt.Errorf("%s: option %q is not supported on this platform", typ, name)
}
