//go:build linux || darwin

package xio

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IPv4 source-specific multicast is group:iface-addr:source
// (IP_ADD_SOURCE_MEMBERSHIP). IPv6 is group:iface-name-or-index:source
// (MCAST_JOIN_SOURCE_GROUP). Keep ipv6-join-source-group as its own option,
// not folded onto ip-add-source-membership.

func setIPv4SourceMembershipFD(fd int, group, iface, source net.IP) error {
	mreq := packIPMreqSource(group, iface, source)
	recordSockoptBytes(fd, unix.IPPROTO_IP, unix.IP_ADD_SOURCE_MEMBERSHIP, mreq[:])
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_ADD_SOURCE_MEMBERSHIP, string(mreq[:])); err != nil {
		return fmt.Errorf("ip-add-source-membership: %w", err)
	}
	return nil
}

func setIPv6SourceMembershipFD(fd int, group net.IP, ifindex uint32, source net.IP) error {
	var req groupSourceReq
	req.Interface = ifindex
	putSockaddrInet6(&req.Group, group)
	putSockaddrInet6(&req.Source, source)
	n := unsafe.Sizeof(req)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&req)), n) // #nosec G103 -- kernel struct group_source_req bytes for MCAST_JOIN_SOURCE_GROUP
	recordSockoptBytes(fd, unix.IPPROTO_IPV6, unix.MCAST_JOIN_SOURCE_GROUP, buf)
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IPV6, unix.MCAST_JOIN_SOURCE_GROUP, string(buf)); err != nil {
		return fmt.Errorf("ipv6-join-source-group: %w", err)
	}
	return nil
}

func putSockaddrInet6(ss *[128]byte, ip net.IP) {
	raw := (*unix.RawSockaddrInet6)(unsafe.Pointer(ss)) // #nosec G103 -- overlay sockaddr_in6 at the start of sockaddr_storage
	*raw = unix.RawSockaddrInet6{}
	raw.Family = unix.AF_INET6
	copy(raw.Addr[:], ip.To16())
	setSockaddrInet6Len(raw)
}
