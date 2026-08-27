//go:build linux

package xio

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyFDOptions applies descriptor-phase options to an already open file.
// Classic applyopts walks the original option list once per phase (xio-fd.c /
// xio-fs.c, tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official
// master af5388c898c7bb60997935aee93c223deba60c4a is the same tree). PH_FD
// therefore applies perm/user/group/flock, generic ioctl-*, o-noatime,
// f-setpipe-sz, and FS_IOC_* fs-* flags in command-line order, then PH_LATE
// append/async/ftruncate/lseek/perm-late. ApplyFDOptions owns those syscalls
// for this *os.File; WrapCommon skips the same open.
//
// o-direct is PH_OPEN only and is not applied here. o-noatime uses F_SETFL
// so inherited descriptors match descriptors opened by socat. Linux ext
// FS_*_FL options (OFUNC_IOCTL_MASK_LONG) use FS_IOC_GETFLAGS/SETFLAGS.
func ApplyFDOptions(f *os.File, s parse.Spec) error {
	return applyFDLifecycleToFile(f, s)
}

// applyLinuxPHFDOption applies Linux-only PH_FD options (o-noatime,
// f-setpipe-sz, FS_IOC_* fs-*) during the shared applyopts-style walk in
// applyFDPhaseLifecycleOptions. Unknown names are ignored.
func applyLinuxPHFDOption(fd int, o parse.Option) error {
	name := parse.CanonicalOptionName(o.Name)
	if mask, ok := linuxExtFSFlagMasks[name]; ok {
		noteLifecycleSyscall("FS_IOC_SETFLAGS")
		if err := applyFSIoctlMask(fd, mask, optionEnabled(o)); err != nil {
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
	enable := optionEnabled(o)
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

// applyFSIoctlMask implements classic applyopt_ioctl_mask_long
// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a): GETFLAGS, val &= ~mask, if bool
// val |= mask, SETFLAGS. =0 therefore clears only the requested bit.
// Privileged flags (FS_APPEND_FL, FS_IMMUTABLE_FL, …) return the kernel
// error; it is never swallowed.
func applyFSIoctlMask(fd int, mask int, enable bool) error {
	val, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	val = applyFSFlagMask(val, mask, enable)
	return ioctlSetLong(fd, unix.FS_IOC_SETFLAGS, val)
}

// ioctlSetLong issues ioctl(2) with a pointer to Go int, matching kernel
// _IOW('f', 2, long) (8-byte long/int on amd64).
func ioctlSetLong(fd int, req uint, val int) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&val))) // #nosec G103 -- There is no safe standard-library API for those calls
	if errno != 0 {
		return errno
	}
	return nil
}
