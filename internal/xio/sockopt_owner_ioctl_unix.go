//go:build unix

package xio

func applyOwnerIoctlPlatform(fd int, name string, pid int) error {
	req, err := ownerIoctlRequest(name)
	if err != nil {
		return err
	}
	// Pointer-to-int32, matching classic applyopt_ioctl
	// (Ioctl(fd, major, (void *)&opt->value)). ioctlSetPointerInt wraps
	// unix.IoctlSetPointerInt across uint vs int request ABIs.
	return ioctlSetPointerInt(fd, req, pid)
}

func ownerIoctlRequest(name string) (ioctlReq, error) {
	switch name {
	case "fiosetown":
		return ioctlReqFromBits(ownerIoctlFIOSETOWN), nil
	case "siocspgrp":
		return ioctlReqSIOCSPGRP(), nil
	default:
		return 0, errNamedOptUnsupported
	}
}
