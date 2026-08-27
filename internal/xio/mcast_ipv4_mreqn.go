//go:build linux

package xio

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func setIPv4MembershipFD(fd int, group, ifaceAddr net.IP, ifindex uint32, idxSet bool) error {
	// Linux IP_ADD_MEMBERSHIP accepts struct ip_mreqn, so a name/index is
	// carried in imr_ifindex instead of being replaced with an interface IPv4
	// address. Darwin and the BSDs expose IPMreqn for IP_MULTICAST_IF, but their
	// IP_ADD_MEMBERSHIP ABI is struct ip_mreq; see mcast_ipv4_mreq.go.
	var mreqn unix.IPMreqn
	copy(mreqn.Multiaddr[:], group.To4())
	if ifaceAddr != nil {
		copy(mreqn.Address[:], ifaceAddr.To4())
	}
	if idxSet {
		mreqn.Ifindex = int32(ifindex) // #nosec G115 -- kernel struct field is signed; classic copies the same uint32 bits
	}
	recordSockoptBytes(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, nil)
	if err := unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreqn); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}
