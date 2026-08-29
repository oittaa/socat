//go:build windows

package xio

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const (
	ipLevelIP        = windows.IPPROTO_IP
	ipOptTTL         = windows.IP_TTL
	ipOptTOS         = windows.IP_TOS
	ipLevelIPv6      = windows.IPPROTO_IPV6
	ipOptUnicastHops = windows.IPV6_UNICAST_HOPS
)

func socketIPFamily(fd int) (ipFamily, error) {
	sa, err := windows.Getsockname(windows.Handle(fd))
	if err != nil {
		return ipFamilyUnknown, err
	}
	switch sa.(type) {
	case *windows.SockaddrInet4:
		return ipFamilyV4, nil
	case *windows.SockaddrInet6:
		return ipFamilyV6, nil
	default:
		return ipFamilyUnknown, nil
	}
}

func applyIPOptions(int, string) error {
	return fmt.Errorf("not supported on this platform")
}

func applyIPv6Tclass(int, int) error {
	return fmt.Errorf("not supported on this platform")
}

func applyIPHdrincl(int, int) error {
	return fmt.Errorf("not supported on this platform")
}
