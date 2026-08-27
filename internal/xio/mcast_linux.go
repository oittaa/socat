//go:build linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func applyFreebindFD(fd int, o parse.Option) error {
	n, err := classicFlagInt(o, -1)
	if err != nil {
		return fmt.Errorf("ip-freebind: %w", err)
	}
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, n); err != nil {
		return fmt.Errorf("ip-freebind: %w", err)
	}
	return nil
}

func applyTransparentFD(fd int, o parse.Option) error {
	n, err := classicFlagInt(o, 1)
	if err != nil {
		return fmt.Errorf("ip-transparent: %w", err)
	}
	// Classic PH_PREBIND TYPE_BOOL OFUNC_SOCKOPT SOL_IP IP_TRANSPARENT
	// (xio-ip.c; tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
	// official master af5388c898c7bb60997935aee93c223deba60c4a). Requires
	// CAP_NET_ADMIN or CAP_NET_RAW; the kernel error is reported, not swallowed.
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, n); err != nil {
		return fmt.Errorf("ip-transparent: %w", err)
	}
	return nil
}

func applyMTUDiscoveryFD(fd int, family membershipFamily, name string, o parse.Option) error {
	n, err := classicFlagInt(o, 2)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	level, opt := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if family == membershipFamilyIPv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
	}
	if err := setSockoptInt(fd, level, opt, n); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
