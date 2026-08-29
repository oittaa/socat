//go:build unix && !aix && !solaris

package xio

import "golang.org/x/sys/unix"

// ioctlSetInt / ioctlSetPointerInt wrap x/sys IoctlSetInt and
// IoctlSetPointerInt. Linux/BSD/Darwin take a uint request; AIX/Solaris
// take int (ioctl_req_int.go).
func ioctlSetInt(fd int, req uint, value int) error {
	return unix.IoctlSetInt(fd, req, value)
}

func ioctlSetPointerInt(fd int, req uint, value int) error {
	return unix.IoctlSetPointerInt(fd, req, value)
}
