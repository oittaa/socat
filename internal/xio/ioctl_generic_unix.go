//go:build linux || darwin

package xio

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// applyGenericIoctlOption implements classic applyopt_ioctl_generic
// (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same function). Parse
// finishes before ioctl(2). Integer request numbers are passed as the
// 32-bit C int pattern zero-extended to unsigned ioctl req (kernel ABI);
// classic stores TYPE_INT in signed int then promotes to unsigned long
// (sign-extends on LP64 when bit 31 is set). Combined with overflow
// rejection in parseClassicCInt, this is an intentional security
// difference from classic strtoul wrapping.
func applyGenericIoctlOption(fd int, o parse.Option) error {
	spec, err := parseGenericIoctl(o)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("ioctl")
	switch spec.kind {
	case ioctlKindVoid:
		if err := ioctlVoid(fd, spec.req); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, NULL): %w", spec.name, fd, spec.req, err)
		}
	case ioctlKindInt:
		if err := unix.IoctlSetInt(fd, spec.req, spec.intVal); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, 0x%x): %w", spec.name, fd, spec.req, spec.intVal, err)
		}
	case ioctlKindIntp:
		// IoctlSetPointerInt stores int32, matching classic pointer-to-C-int
		// (opt->value2.u_int). C int is 32-bit on linux/darwin; a Go int
		// pointer would be the wrong width on amd64.
		if err := unix.IoctlSetPointerInt(fd, spec.req, spec.intVal); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, int*): %w", spec.name, fd, spec.req, err)
		}
	case ioctlKindBin:
		if err := ioctlBytes(fd, spec.req, spec.bin); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, bin): %w", spec.name, fd, spec.req, err)
		}
	case ioctlKindString:
		// Pin a NUL-terminated buffer (classic Ioctl(..., u_string)).
		// IoctlSetString does the same conversion; doing it here keeps
		// KeepAlive next to SYS_IOCTL like ioctl-bin.
		buf := append([]byte(spec.str), 0)
		if err := ioctlBytes(fd, spec.req, buf); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, string): %w", spec.name, fd, spec.req, err)
		}
	default:
		return fmt.Errorf("unknown ioctl option %q", spec.name)
	}
	return nil
}

func ioctlVoid(fd int, req uint) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), 0) // #nosec G103 -- There is no safe standard-library API for ioctl(fd, req, NULL)
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlBytes(fd int, req uint, data []byte) error {
	var arg uintptr
	if len(data) > 0 {
		arg = uintptr(unsafe.Pointer(&data[0])) // #nosec G103 -- classic ioctl-bin passes the dalan buffer; slice header is not passed
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), arg) // #nosec G103 -- There is no safe standard-library API for ioctl with a caller buffer
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}
