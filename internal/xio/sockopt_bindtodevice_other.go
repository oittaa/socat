//go:build !linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyBindToDevice rejects classic so-bindtodevice / if off Linux.
// SO_BINDTODEVICE is a Linux socket option (xio-socket.c, #ifdef SO_BINDTODEVICE).
func applyBindToDevice(_ int, s parse.Spec) error {
	if _, ok := s.OptionNamed("bindtodevice"); ok {
		return fmt.Errorf("bindtodevice is not supported on this platform")
	}
	return nil
}
