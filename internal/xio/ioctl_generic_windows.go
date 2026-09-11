//go:build windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

func applyConfiguredGenericIoctl(_ int, action addrconfig.FileAction) error {
	return fmt.Errorf("%s: not supported on windows", action.Name)
}
