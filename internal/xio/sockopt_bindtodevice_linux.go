//go:build linux

package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// applyBindToDeviceOption sets SO_BINDTODEVICE (aliases so-bindtodevice /
// if / interface). Linux only; applies after socket().
func applyBindToDeviceOption(fd int, o parse.Option) error {
	name := strings.TrimSpace(o.Value)
	if !o.Has || name == "" {
		return fmt.Errorf("bindtodevice: requires a value")
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); err != nil {
		return fmt.Errorf("bindtodevice: %w", err)
	}
	return nil
}
