//go:build linux

package xio

import (
	"errors"
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyFDOptions applies descriptor-phase options to an already open file.
// O_NOATIME is deliberately set with F_SETFL so inherited descriptors work
// the same way as descriptors opened by socat.
func ApplyFDOptions(f *os.File, s parse.Spec) error {
	if f == nil {
		return nil
	}
	noatime, _ := optionBoolAny(s, "o-noatime", "noatime")
	pipeSizeValue, setPipeSize := optionValueAny(s, "f-setpipe-sz", "pipesz")
	pipeSize := 0
	if setPipeSize {
		var err error
		pipeSize, err = ParseIntAny(pipeSizeValue)
		if err != nil || pipeSize <= 0 {
			return fmt.Errorf("f-setpipe-sz: invalid value %q", pipeSizeValue)
		}
	}
	if !noatime && !setPipeSize {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		if noatime {
			flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
			if e == nil {
				_, e = unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NOATIME)
			}
			if e != nil {
				optionErr = fmt.Errorf("o-noatime: %w", e)
				return
			}
		}
		if setPipeSize {
			if _, e := unix.FcntlInt(fd, unix.F_SETPIPE_SZ, pipeSize); e != nil {
				optionErr = fmt.Errorf("f-setpipe-sz: %w", e)
			}
		}
	})
	return errors.Join(controlErr, optionErr)
}
