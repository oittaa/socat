//go:build windows

package dtls13

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	windowsIPDontFragment = 14
	windowsIPv6DontFrag   = 14
)

func setUnfragmentedDF(rawConn syscall.RawConn) (bool, error) {
	var err4, err6 error
	if err := rawConn.Control(func(fd uintptr) {
		err4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windowsIPDontFragment, 1)
		err6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windowsIPv6DontFrag, 1)
	}); err != nil {
		return false, err
	}
	if err4 != nil && err6 != nil {
		return false, errors.Join(err4, err6)
	}
	return true, nil
}
