//go:build linux

package xio

import (
	"fmt"
	"math"
	"net"

	"golang.org/x/sys/unix"
)

func setIPv4MembershipFD(fd int, group, ifaceAddr net.IP, ifindex uint32, idxSet bool) error {
	// Linux IP_ADD_MEMBERSHIP accepts struct ip_mreqn, so a name/index is
	// carried in imr_ifindex instead of being replaced with an interface IPv4
	// address. macOS IP_ADD_MEMBERSHIP uses struct ip_mreq; see
	// mcast_ipv4_mreq.go.
	var mreqn unix.IPMreqn
	copy(mreqn.Multiaddr[:], group.To4())
	if ifaceAddr != nil {
		copy(mreqn.Address[:], ifaceAddr.To4())
	}
	if idxSet {
		if ifindex > math.MaxInt32 {
			return fmt.Errorf("ip-add-membership: interface index %d out of range", ifindex)
		}
		mreqn.Ifindex = int32(ifindex)
	}
	recordSockoptBytes(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, nil)
	if err := unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreqn); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}
