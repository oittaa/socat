package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

func isTermiosOption(name string) bool {
	groups, ok := OptionCapsFor(name)
	if !ok {
		return false
	}
	for _, g := range groups {
		if g == CapTermios {
			return true
		}
	}
	return false
}

// RejectUnsupportedTermios fails when a spec requests a termios option on a
// platform that does not implement termios (Windows). Same shape as
// RejectUnsupportedIPAncillary: do not accept the option as a silent no-op.
func RejectUnsupportedTermios(s parse.Spec) error {
	if FeatureTERMIOS {
		return nil
	}
	for _, option := range s.Options {
		if isTermiosOption(option.OriginalSpelling()) || isTermiosOption(option.Name) {
			return fmt.Errorf("%s: option %q is not supported on this platform", s.Type, option.Name)
		}
	}
	return nil
}
