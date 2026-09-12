//go:build linux || darwin

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

// ValidateDescriptorModeOptions rejects Cygwin-only options on Unix even
// though the shared help table knows their names for Windows builds.
func ValidateDescriptorModeOptions(s addrconfig.Address) error {
	if s.Common.Binary.Set {
		return fmt.Errorf("%s: option %q is not supported on this platform", s.Type, "binary")
	}
	if s.Common.Text.Set {
		return fmt.Errorf("%s: option %q is not supported on this platform", s.Type, "text")
	}
	for _, action := range s.File.Actions {
		if action.Kind == addrconfig.FileActionNoInherit {
			return fmt.Errorf("%s: option %q is not supported on this platform", s.Type, action.Name)
		}
	}
	return nil
}

func applyConfiguredDescriptorMode(config addrconfig.Address, stream relay.Stream) (relay.Stream, error) {
	if err := ValidateDescriptorModeOptions(config); err != nil {
		return nil, err
	}
	return stream, nil
}
