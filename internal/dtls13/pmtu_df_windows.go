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
		h := windows.Handle(fd)
		err4 = setWindowsProbeOrDF(h, false)
		err6 = setWindowsProbeOrDF(h, true)
	}); err != nil {
		return false, err
	}
	if err4 != nil && err6 != nil {
		return false, errors.Join(err4, err6)
	}
	return true, nil
}

func setWindowsProbeOrDF(fd windows.Handle, ipv6 bool) error {
	proto, discover, dontFrag := int(windows.IPPROTO_IP), windows.IP_MTU_DISCOVER, windowsIPDontFragment
	if ipv6 {
		proto, discover, dontFrag = int(windows.IPPROTO_IPV6), windows.IPV6_MTU_DISCOVER, windowsIPv6DontFrag
	}
	// Datagram IP_PMTUDISC_PROBE sets DF and limits against the interface MTU,
	// not the cached path MTU. IP_PMTUDISC_DO is not used.
	if err := windows.SetsockoptInt(fd, proto, discover, windows.IP_PMTUDISC_PROBE); err == nil {
		return nil
	}
	return windows.SetsockoptInt(fd, proto, dontFrag, 1)
}
