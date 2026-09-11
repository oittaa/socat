//go:build linux || darwin

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

func applyOwnerIoctlPlatform(fd int, id addrconfig.NamedSocket, pid int) error {
	req, err := ownerIoctlRequest(id)
	if err != nil {
		return err
	}
	// Pointer to int32.
	return unix.IoctlSetPointerInt(fd, req, pid)
}

func ownerIoctlRequest(id addrconfig.NamedSocket) (uint, error) {
	switch id {
	case addrconfig.NamedSocketFIOSETOWN:
		return ownerIoctlFIOSETOWN, nil
	case addrconfig.NamedSocketSIOCSPGRP:
		return uint(unix.SIOCSPGRP), nil
	default:
		return 0, errNamedOptUnsupported
	}
}
