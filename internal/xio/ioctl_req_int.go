//go:build aix || solaris

package xio

import "golang.org/x/sys/unix"

// AIX/Solaris golang.org/x/sys/unix IoctlSetInt / IoctlSetPointerInt take
// int request numbers (ioctl_signed.go). Store req as the 32-bit pattern
// zero-extended to uint and convert here.
func ioctlSetInt(fd int, req uint, value int) error {
	return unix.IoctlSetInt(fd, int(req), value)
}

func ioctlSetPointerInt(fd int, req uint, value int) error {
	return unix.IoctlSetPointerInt(fd, int(req), value)
}
