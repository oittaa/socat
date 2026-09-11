//go:build linux

package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyFDOptions applies descriptor options to an already open file in
// command-line order (after open, then late). o-direct is open(2) only.
// o-noatime uses F_SETFL; fs-* uses FS_IOC_*.
func ApplyFDOptions(f *os.File, s parse.Spec) error {
	return ApplyFDOptionsSkip(f, s, FDSkip{})
}

// ApplyFDOptionsSkip applies descriptor options, skipping opener-owned names.
func ApplyFDOptionsSkip(f *os.File, s parse.Spec, skip FDSkip) error {
	return applyFDLifecycleToFile(f, s, skip)
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

func applyConfiguredLinuxPHFDAction(fd int, action addrconfig.FileAction) error {
	switch action.Kind {
	case addrconfig.FileActionFSFlag:
		mask, ok := linuxExtFSFlagMasks[action.Text]
		if !ok {
			return nil
		}
		noteLifecycleSyscall("FS_IOC_SETFLAGS")
		if err := applyFSIoctlMask(fd, mask, action.Enabled); err != nil {
			return fmt.Errorf("%s: %w", action.Name, err)
		}
	case addrconfig.FileActionNoAtime:
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			return fmt.Errorf("o-noatime: %w", err)
		}
		if action.Enabled {
			flags |= unix.O_NOATIME
		} else {
			flags &^= unix.O_NOATIME
		}
		noteLifecycleSyscall("F_SETFL")
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
			return fmt.Errorf("o-noatime: %w", err)
		}
	case addrconfig.FileActionPipeSize:
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return fmt.Errorf("f-setpipe-sz: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFIFO {
			return fmt.Errorf("f-setpipe-sz: not a pipe")
		}
		noteLifecycleSyscall("F_SETPIPE_SZ")
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETPIPE_SZ, action.Value); err != nil {
			return fmt.Errorf("f-setpipe-sz: %w", err)
		}
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
	bits, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	val := int(int32(bits)) // #nosec G115 -- preserve the kernel's 32-bit flag word
	val = applyFSFlagMask(val, mask, enable)
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, val)
}
