//go:build linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// applyRouterAlertFD sets IPPROTO_IP IP_ROUTER_ALERT. Linux accepts it on
// SOCK_RAW IPv4 except protocol 255 (IPPROTO_RAW), where setsockopt returns
// EINVAL. TCP/UDP return EINVAL. IPv6 raw with IPPROTO_IP returns
// ENOPROTOOPT. Those cases are rejected instead of forwarding the kernel
// error as a generic setsockopt failure.
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
