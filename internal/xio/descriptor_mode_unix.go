//go:build linux || darwin

package xio

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ValidateDescriptorModeOptions rejects Cygwin-only options on Unix even
// though the shared help table knows their names for Windows builds.
func ValidateDescriptorModeOptions(s parse.Spec) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	return validateConfiguredDescriptorMode(config)
}

func validateConfiguredDescriptorMode(config addrconfig.Address) error {
	if config.Common.Binary.Set {
		return fmt.Errorf("%s: option %q is not supported on this platform", config.Type, "binary")
	}
	if config.Common.Text.Set {
		return fmt.Errorf("%s: option %q is not supported on this platform", config.Type, "text")
	}
	for _, action := range config.File.Actions {
		if action.Kind == addrconfig.FileActionNoInherit {
			return fmt.Errorf("%s: option %q is not supported on this platform", config.Type, action.Name)
		}
	}
	return nil
}

func applyConfiguredDescriptorMode(config addrconfig.Address, stream relay.Stream) (relay.Stream, error) {
	if err := validateConfiguredDescriptorMode(config); err != nil {
		return nil, err
	}
	return stream, nil
}
