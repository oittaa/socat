//go:build solaris

package xio

import "golang.org/x/sys/unix"

func ioctlReqSIOCSPGRP() ioctlReq {
	// Native signed constant (-0x7ffb8cf8). uint(unix.SIOCSPGRP) overflows.
	return unix.SIOCSPGRP
}
