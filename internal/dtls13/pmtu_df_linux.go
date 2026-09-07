//go:build linux

package dtls13

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// PMTUDISC_PROBE sets DF and sizes sends against the interface MTU, not the
// cached path MTU. Incoming PTB may still update that cache. PMTUDISC_DO is
// not used: it would fail sends larger than the cached path MTU.
func setUnfragmentedDF(rawConn syscall.RawConn) (bool, error) {
	var err4, err6 error
	if err := rawConn.Control(func(fd uintptr) {
		err4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		err6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	}); err != nil {
		return false, err
	}
	if err4 != nil && err6 != nil {
		return false, errors.Join(err4, err6)
	}
	return true, nil
}
