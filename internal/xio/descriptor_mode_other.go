//go:build !windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func hasPlatformFDLifecycleOptions(parse.Spec) bool { return false }

// ValidateDescriptorModeOptions rejects Cygwin-only options on Unix even
// though the shared help table knows their names for Windows builds.
func ValidateDescriptorModeOptions(s parse.Spec) error {
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "binary", "text", "noinherit":
			return fmt.Errorf("%s: option %q is not supported on this platform", s.Type, o.OriginalSpelling())
		}
	}
	return nil
}

func applyDescriptorMode(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := ValidateDescriptorModeOptions(s); err != nil {
		return nil, err
	}
	return stream, nil
}
