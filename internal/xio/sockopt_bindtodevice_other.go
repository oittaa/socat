//go:build darwin || windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyBindToDeviceOption rejects classic so-bindtodevice / if off Linux.
// SO_BINDTODEVICE is a Linux socket option (xio-socket.c, #ifdef SO_BINDTODEVICE).
func applyBindToDeviceOption(_ int, _ parse.Option) error {
	return fmt.Errorf("bindtodevice is not supported on this platform")
}
