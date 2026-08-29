//go:build linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// applyRouterAlertFD is classic OFUNC_SOCKOPT SOL_IP IP_ROUTER_ALERT
// (xio-ip.c TYPE_INT PH_PASTSOCKET; tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree). Linux accepts
// the option on SOCK_RAW IPv4 sockets except protocol 255 (IPPROTO_RAW),
// where setsockopt returns EINVAL. TCP/UDP return EINVAL. IPv6 raw with
// SOL_IP returns ENOPROTOOPT. This port rejects those cases instead of
// forwarding the kernel error as a generic setsockopt failure.
func applyRouterAlertFD(fd int, o parse.Option) error {
	spelling := optionSpelling(o)
	n, err := classicFlagInt(o, -1)
	if err != nil {
		return fmt.Errorf("%s: %w", spelling, err)
	}
	family, err := socketIPFamily(fd)
	if err != nil {
		return err
	}
	if family == ipFamilyV6 {
		return fmt.Errorf("%s: not supported on IPv6", spelling)
	}
	soType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return fmt.Errorf("%s: %w", spelling, err)
	}
	if soType != unix.SOCK_RAW {
		return fmt.Errorf("%s: not supported with this address type", spelling)
	}
	proto, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return fmt.Errorf("%s: %w", spelling, err)
	}
	if proto == unix.IPPROTO_RAW {
		return fmt.Errorf("%s: not supported on IPPROTO_RAW sockets", spelling)
	}
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_ROUTER_ALERT, n); err != nil {
		return fmt.Errorf("%s: %w", spelling, err)
	}
	return nil
}
