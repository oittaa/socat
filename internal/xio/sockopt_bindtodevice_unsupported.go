//go:build darwin || windows

package xio

import (
	"fmt"
)

func applyBindToDeviceName(_ int, _ string) error {
	return fmt.Errorf("bindtodevice is not supported on this platform")
}
