//go:build unix

package xio

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	ipLevelIP        = unix.IPPROTO_IP
	ipOptTTL         = unix.IP_TTL
	ipOptTOS         = unix.IP_TOS
	ipLevelIPv6      = unix.IPPROTO_IPV6
	ipOptUnicastHops = unix.IPV6_UNICAST_HOPS
)

func socketIPFamily(fd int) (ipFamily, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return ipFamilyUnknown, err
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		return ipFamilyV4, nil
	case *unix.SockaddrInet6:
		return ipFamilyV6, nil
	default:
		return ipFamilyUnknown, nil
	}
}

func applyIPOptions(fd int, value string) error {
	b, err := ParseHexOpt(value)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return fmt.Errorf("empty value")
	}
	return unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(b))
}

func applyIPv6Tclass(fd, n int) error {
	return setSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n)
}
