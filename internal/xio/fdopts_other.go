//go:build !linux

package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
)

func ApplyFDOptions(_ *os.File, s parse.Spec) error {
	if enabled, ok := optionBoolAny(s, "o-noatime", "noatime"); ok && enabled {
		return fmt.Errorf("o-noatime: not supported on this platform")
	}
	if _, ok := optionValueAny(s, "f-setpipe-sz", "pipesz"); ok {
		return fmt.Errorf("f-setpipe-sz: not supported on this platform")
	}
	return nil
}
