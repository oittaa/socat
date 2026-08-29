package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

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
