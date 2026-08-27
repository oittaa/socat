//go:build unix && !linux && !darwin && !freebsd

package xio

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func setIPv4MembershipFD(fd int, group, ifaceAddr net.IP, _ uint32, idxSet bool) error {
	if idxSet {
		return fmt.Errorf("ip-add-membership: interface name/index form is not supported on this platform")
	}
	var mreq unix.IPMreq
	copy(mreq.Multiaddr[:], group.To4())
	if ifaceAddr != nil {
		copy(mreq.Interface[:], ifaceAddr.To4())
	}
	recordSockoptBytes(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, nil)
	if err := unix.SetsockoptIPMreq(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}
