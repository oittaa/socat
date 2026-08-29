//go:build darwin || windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyBindToDeviceOption rejects bindtodevice off Linux.
func applyBindToDeviceOption(_ int, _ parse.Option) error {
	return fmt.Errorf("bindtodevice is not supported on this platform")
}
