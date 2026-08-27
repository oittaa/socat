//go:build linux

package xio

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyFDOptions applies descriptor-phase options to an already open file.
// O_NOATIME is deliberately set with F_SETFL so inherited descriptors work
// the same way as descriptors opened by socat. o-direct is PH_OPEN only and
// is not applied here.
//
// Classic phases (xio-fd.c / applyopt_fcntl, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba): PH_FD perm/user/group/flock and
// o-noatime, then PH_LATE append/async/ftruncate/lseek/perm-late. ApplyFDOptions
// owns those lifecycle syscalls for this *os.File; WrapCommon skips the same open.
// Linux ext FS_*_FL options (xio-fs.c OFUNC_IOCTL_MASK_LONG, same tag and
// official master af5388c898c7bb60997935aee93c223deba60c4a) run at PH_FD via
// FS_IOC_GETFLAGS/SETFLAGS. Each occurrence is applied in command-line order.
func ApplyFDOptions(f *os.File, s parse.Spec) error {
	if f == nil {
		return nil
	}
	noatime, _ := optionBoolAny(s, "o-noatime", "noatime")
	fsOps := linuxExtFSFlagOps(s)
	pipeSizeValue, setPipeSize := optionValueAny(s, "f-setpipe-sz", "pipesz")
	pipeSize := 0
	if setPipeSize {
		var err error
		pipeSize, err = ParseIntAny(pipeSizeValue)
		if err != nil || pipeSize <= 0 {
			return fmt.Errorf("f-setpipe-sz: invalid value %q", pipeSizeValue)
		}
	}
	needLifecycle := hasFDLifecycleOptions(s)
	if !noatime && !setPipeSize && len(fsOps) == 0 {
		return applyFDLifecycleToFile(f, s)
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		n := int(fd)
		if needLifecycle {
			if fdLifecycleTestHook != nil {
				fdLifecycleTestHook(n)
			}
			if e := applyFDPhaseLifecycle(n, s); e != nil {
				optionErr = e
				return
			}
		}
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
		for _, op := range fsOps {
			if e := applyFSIoctlMask(n, op.mask, op.enable); e != nil {
				optionErr = fmt.Errorf("%s: %w", op.name, e)
				return
			}
		}
		if setPipeSize {
			if _, e := unix.FcntlInt(fd, unix.F_SETPIPE_SZ, pipeSize); e != nil {
				optionErr = fmt.Errorf("f-setpipe-sz: %w", e)
				return
			}
		}
		if needLifecycle {
			if e := applyLateLifecycle(n, s); e != nil {
				optionErr = e
			}
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	if needLifecycle {
		markFDLifecycleApplied(f)
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
