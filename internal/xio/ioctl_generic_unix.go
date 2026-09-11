//go:build linux || darwin

package xio

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

func applyConfiguredGenericIoctl(fd int, action addrconfig.FileAction) error {
	request := uint(action.Request)
	noteLifecycleSyscall("ioctl")
	switch action.ValueKind {
	case 1:
		if err := ioctlVoid(fd, request); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, NULL): %w", action.Name, fd, request, err)
		}
	case 2:
		if err := unix.IoctlSetInt(fd, request, action.Value); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, 0x%x): %w", action.Name, fd, request, action.Value, err)
		}
	case 3:
		if err := unix.IoctlSetPointerInt(fd, request, action.Value); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, int*): %w", action.Name, fd, request, err)
		}
	case 4:
		payload := append([]byte(nil), action.Bytes...)
		if err := ioctlBytes(fd, request, payload); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, bin): %w", action.Name, fd, request, err)
		}
	case 5:
		data := append([]byte(action.Text), 0)
		if err := ioctlBytes(fd, request, data); err != nil {
			return fmt.Errorf("%s: ioctl(%d, 0x%x, string): %w", action.Name, fd, request, err)
		}
	default:
		return fmt.Errorf("unknown ioctl option %q", action.Name)
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
		arg = uintptr(unsafe.Pointer(&data[0])) // #nosec G103 -- ioctl-bin passes the dalan buffer; slice header is not passed
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), arg) // #nosec G103 -- There is no safe standard-library API for ioctl with a caller buffer
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}
