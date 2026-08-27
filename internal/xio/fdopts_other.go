//go:build !linux

package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
)

func ApplyFDOptions(f *os.File, s parse.Spec) error {
	if enabled, ok := optionBoolAny(s, "o-noatime", "noatime"); ok && enabled {
		return fmt.Errorf("o-noatime: not supported on this platform")
	}
	for _, op := range linuxExtFSFlagOps(s) {
		if op.enable {
			return fmt.Errorf("%s: not supported on this platform", op.name)
		}
	}
	if _, ok := optionValueAny(s, "f-setpipe-sz", "pipesz"); ok {
		return fmt.Errorf("f-setpipe-sz: not supported on this platform")
	}
	return applyFDLifecycleToFile(f, s)
}
