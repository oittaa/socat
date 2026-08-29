//go:build unix

package xio

import "golang.org/x/sys/unix"

func applyOwnerIoctlPlatform(fd int, name string, pid int) error {
	req, err := ownerIoctlRequest(name)
	if err != nil {
		return err
	}
	// Pointer-to-int32, matching classic applyopt_ioctl
	// (Ioctl(fd, major, (void *)&opt->value)).
	return unix.IoctlSetPointerInt(fd, req, pid)
}

func ownerIoctlRequest(name string) (uint, error) {
	switch name {
	case "fiosetown":
		return ownerIoctlFIOSETOWN, nil
	case "siocspgrp":
		return uint(unix.SIOCSPGRP), nil
	default:
		return 0, errNamedOptUnsupported
	}
}
