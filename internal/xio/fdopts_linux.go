//go:build linux

package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyFDOptions applies descriptor options to an already open file in
// command-line order (after open, then late). WrapCommon skips the same
// *os.File. o-direct is open(2) only. o-noatime uses F_SETFL; fs-* uses FS_IOC_*.
func ApplyFDOptions(f *os.File, s parse.Spec) error {
	return applyFDLifecycleToFile(f, s)
}

// applyLinuxPHFDOption applies Linux-only after-open options (o-noatime,
// f-setpipe-sz, fs-* ioctl flags) during applyFDPhaseLifecycleOptions.
// Unknown names are ignored.
func applyLinuxPHFDOption(fd int, o parse.Option) error {
	name := parse.CanonicalOptionName(o.Name)
	if mask, ok := linuxExtFSFlagMasks[name]; ok {
		noteLifecycleSyscall("FS_IOC_SETFLAGS")
		if err := applyFSIoctlMask(fd, mask, o.Active()); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	switch name {
	case "o-noatime", "noatime":
		return applyOneNoatime(fd, o)
	case "f-setpipe-sz", "pipesz":
		return applyOnePipeSize(fd, o)
	}
	return nil
}

func applyOneNoatime(fd int, o parse.Option) error {
	enable := o.Active()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("o-noatime: %w", err)
	}
	if enable {
		flags |= unix.O_NOATIME
	} else {
		flags &^= unix.O_NOATIME
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("o-noatime: %w", err)
	}
	return nil
}

func applyOnePipeSize(fd int, o parse.Option) error {
	pipeSize, err := ParseIntAny(o.Value)
	if err != nil || pipeSize <= 0 {
		return fmt.Errorf("f-setpipe-sz: invalid value %q", o.Value)
	}
	noteLifecycleSyscall("F_SETPIPE_SZ")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETPIPE_SZ, pipeSize); err != nil {
		return fmt.Errorf("f-setpipe-sz: %w", err)
	}
	return nil
}

// applyFSIoctlMask does GETFLAGS, val &= ~mask, then |= mask when enable,
// then SETFLAGS. =0 clears only the requested bit. Privileged flags
// (FS_APPEND_FL, FS_IMMUTABLE_FL, …) return the kernel error.
func applyFSIoctlMask(fd int, mask int, enable bool) error {
	val, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	val = applyFSFlagMask(val, mask, enable)
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, val)
}
