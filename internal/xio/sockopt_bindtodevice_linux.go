//go:build linux

package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// applyBindToDevice sets SO_BINDTODEVICE (classic opt_so_bindtodevice,
// aliases so-bindtodevice / if / interface). PH_PASTSOCKET, TYPE_NAME, Linux only.
// Classic: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree.
func applyBindToDevice(fd int, s parse.Spec) error {
	o, ok := s.OptionNamed("bindtodevice")
	if !ok {
		return nil
	}
	name := strings.TrimSpace(o.Value)
	if !o.Has || name == "" {
		return fmt.Errorf("bindtodevice: requires a value")
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); err != nil {
		return fmt.Errorf("bindtodevice: %w", err)
	}
	return nil
}
