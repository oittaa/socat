//go:build darwin || windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

func applyRouterAlertFD(_ int, o parse.Option) error {
	return fmt.Errorf("%s: not supported on this platform", optionSpelling(o))
}
