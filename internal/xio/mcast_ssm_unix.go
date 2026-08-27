//go:build linux || darwin || freebsd

package xio

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IPv4 source-specific multicast is classic TYPE_IP_MREQ_SOURCE
// (xio-ip.c xiotype_ip_add_source_membership / xioapply_ip_add_source_membership).
// IPv6 is TYPE_GROUP_SOURCE_REQ / MCAST_JOIN_SOURCE_GROUP
// (xio-ip6.c; keep ipv6-join-source-group as its own option, not folded onto
// ip-add-source-membership). tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree.

type parsedSourceMcast struct {
	group     net.IP
	ifaceAddr net.IP // IPv4 interface address
	source    net.IP
	token     string // IPv6 interface name or index
}

func parseSourceMcastSpec(spec, optionName string, family membershipFamily) (parsedSourceMcast, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return parsedSourceMcast{}, fmt.Errorf("%s: expected group:iface:source, got %q", optionName, spec)
	}
	fields, err := splitMcastFields(spec)
	if err != nil {
		return parsedSourceMcast{}, fmt.Errorf("%s: %w", optionName, err)
	}
	if len(fields) != 3 {
		return parsedSourceMcast{}, fmt.Errorf("%s: expected group:iface:source, got %q", optionName, spec)
	}
	group, err := parseMcastGroup(fields[0], optionName)
	if err != nil {
		return parsedSourceMcast{}, fmt.Errorf("%s: %w", optionName, err)
	}
	source, err := parseMcastGroup(fields[2], optionName)
	if err != nil {
		return parsedSourceMcast{}, fmt.Errorf("%s: bad source %q", optionName, strings.TrimSpace(fields[2]))
	}
	iface := strings.TrimSpace(fields[1])
	if iface == "" {
		return parsedSourceMcast{}, fmt.Errorf("%s: expected group:iface:source, got %q", optionName, spec)
	}
	if family == membershipFamilyIPv4 {
		addr, err := resolveMcastIPv4Address(iface)
		if err != nil {
			return parsedSourceMcast{}, fmt.Errorf("%s: bad interface address %q", optionName, iface)
		}
		return parsedSourceMcast{group: group, ifaceAddr: addr, source: source}, nil
	}
	return parsedSourceMcast{group: group, token: iface, source: source}, nil
}

// sockaddrStorage is C struct sockaddr_storage (128 bytes, 8-byte aligned).
// golang.org/x/sys/unix.SockaddrStorage exists on Linux only.
type sockaddrStorage struct {
	_ [16]uint64
}

// groupSourceReq matches Linux/BSD struct group_source_req. Go inserts
// alignment padding after Interface so sockaddrStorage stays 8-byte aligned
// (264 bytes on 64-bit).
type groupSourceReq struct {
	Interface uint32
	Group     sockaddrStorage
	Source    sockaddrStorage
}

func applySourceMembershipFD(fd int, family membershipFamily, name, spec string) error {
	parsed, err := parseSourceMcastSpec(spec, name, family)
	if err != nil {
		return err
	}
	if family == membershipFamilyIPv4 {
		if parsed.group.To4() == nil {
			return fmt.Errorf("%s: IPv4 source membership requires an IPv4 group, got %s", name, parsed.group)
		}
		if parsed.source.To4() == nil {
			return fmt.Errorf("%s: IPv4 source membership requires an IPv4 source, got %s", name, parsed.source)
		}
		return setIPv4SourceMembershipFD(fd, parsed.group.To4(), parsed.ifaceAddr, parsed.source.To4())
	}
	sockFamily, err := socketIPFamily(fd)
	if err != nil {
		return err
	}
	if sockFamily == ipFamilyV4 {
		return fmt.Errorf("%s: not supported on IPv4", name)
	}
	if parsed.group.To4() != nil {
		return fmt.Errorf("%s: IPv6 source membership requires an IPv6 group, got %s", name, parsed.group)
	}
	if parsed.source.To4() != nil {
		return fmt.Errorf("%s: IPv6 source membership requires an IPv6 source, got %s", name, parsed.source)
	}
	idx, idxSet, err := resolveMcastInterface(parsedMcast{token: parsed.token}, name)
	if err != nil {
		return err
	}
	if !idxSet {
		return fmt.Errorf("%s: expected interface name or index", name)
	}
	return setIPv6SourceMembershipFD(fd, parsed.group, idx, parsed.source)
}

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

func putSockaddrInet6(ss *sockaddrStorage, ip net.IP) {
	raw := (*unix.RawSockaddrInet6)(unsafe.Pointer(ss)) // #nosec G103 -- overlay sockaddr_in6 at the start of sockaddr_storage
	*raw = unix.RawSockaddrInet6{}
	raw.Family = unix.AF_INET6
	copy(raw.Addr[:], ip.To16())
	setSockaddrInet6Len(raw)
}
