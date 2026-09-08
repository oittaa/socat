//go:build windows

package dtls13

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func setUnfragmentedDF(rawConn syscall.RawConn) (bool, error) {
	var setupErr error
	if err := rawConn.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		addr, err := windows.Getsockname(h)
		if err != nil {
			setupErr = err
			return
		}
		if _, ipv6 := addr.(*windows.SockaddrInet6); ipv6 {
			v6only, err := windows.GetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err != nil {
				setupErr = err
				return
			}
			setupErr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER, windows.IP_PMTUDISC_PROBE)
			if v6only != 0 {
				return
			}
		}
		setupErr = errors.Join(setupErr, windows.SetsockoptInt(h, windows.IPPROTO_IP, windows.IP_MTU_DISCOVER, windows.IP_PMTUDISC_PROBE))
	}); err != nil {
		return false, err
	}
	// DF alone does not prove that probes can bypass a stale PMTU cache.
	return setupErr == nil, setupErr
}
