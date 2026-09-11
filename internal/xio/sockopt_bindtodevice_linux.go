//go:build linux

package xio

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// applyBindToDeviceName sets SO_BINDTODEVICE (aliases so-bindtodevice /
// if / interface). Linux only; applies after socket().
func applyBindToDeviceName(fd int, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("bindtodevice: requires a value")
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); err != nil {
		return fmt.Errorf("bindtodevice: %w", err)
	}
	return nil
}
