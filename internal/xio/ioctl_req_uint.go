//go:build unix && !aix && !solaris

package xio

import "golang.org/x/sys/unix"

// ioctlReq matches golang.org/x/sys/unix IoctlSetInt / IoctlSetPointerInt /
// IoctlGetInt on Linux, Darwin, and BSD (ioctl_unsigned.go: req uint).
type ioctlReq = uint

func ioctlSetInt(fd int, req ioctlReq, value int) error {
	return unix.IoctlSetInt(fd, req, value)
}

func ioctlSetPointerInt(fd int, req ioctlReq, value int) error {
	return unix.IoctlSetPointerInt(fd, req, value)
}

func ioctlGetInt(fd int, req ioctlReq) (int, error) {
	return unix.IoctlGetInt(fd, req)
}

func ioctlReqFromBits(bits uint32) ioctlReq {
	return ioctlReq(bits)
}

func ioctlReqFromParsed(req uint) ioctlReq {
	return ioctlReq(req)
}

func ioctlReqSIOCSPGRP() ioctlReq {
	return unix.SIOCSPGRP
}
