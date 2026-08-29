//go:build aix

package xio

import "golang.org/x/sys/unix"

func ioctlReqSIOCSPGRP() ioctlReq {
	// x/sys AIX ppc64 defines SIOCSPGRP as 0xffffffff80047308, which does
	// not fit int. Keep the low 32 bits as the signed ioctl request
	// (same pattern as Solaris -0x7ffb8cf8 / BSD 0x80047308).
	bits := uint64(unix.SIOCSPGRP)
	return ioctlReq(int32(uint32(bits)))
}
