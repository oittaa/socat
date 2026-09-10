//go:build windows

package cli

import (
	"fmt"
	"github.com/oittaa/socat/internal/parse"
)

func validateUnixTightSocklen(option parse.Option) error {
	if err := validateOptionalBool(option); err != nil {
		return err
	}
	return fmt.Errorf("%s: not supported on this platform", option.Name)
}
