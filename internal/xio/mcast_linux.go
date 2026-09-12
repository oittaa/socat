//go:build linux

package xio

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func applyFreebindValue(fd int, n int) error {
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, n); err != nil {
		return fmt.Errorf("ip-freebind: %w", err)
	}
	return nil
}

func applyTransparentValue(fd int, n int) error {
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, n); err != nil {
		return fmt.Errorf("ip-transparent: %w", err)
	}
	return nil
}

func applyMTUDiscoveryValue(fd int, family membershipFamily, name string, n int) error {
	level, opt := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if family == membershipFamilyIPv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
	}
	if err := setSockoptInt(fd, level, opt, n); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
