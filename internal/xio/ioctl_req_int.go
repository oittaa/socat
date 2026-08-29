//go:build aix || solaris

package xio

import "golang.org/x/sys/unix"

// ioctlReq matches golang.org/x/sys/unix IoctlSetInt / IoctlSetPointerInt /
// IoctlGetInt on AIX/Solaris (ioctl_signed.go: req int). High-bit 32-bit
// ioctl numbers such as SIOCSPGRP are negative signed constants on Solaris
// (uint(unix.SIOCSPGRP) overflows) and a 64-bit 0xffffffff… pattern on AIX
// ppc64 (does not fit int). ioctlReqSIOCSPGRP maps both to this native int
// request type; ioctlReqFromBits sign-extends a 32-bit filio pattern.
type ioctlReq = int

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
	return ioctlReq(int32(bits))
}

func ioctlReqFromParsed(req uint) ioctlReq {
	return ioctlReq(req)
}
