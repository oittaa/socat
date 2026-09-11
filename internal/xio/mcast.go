//go:build linux || darwin

package xio

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

func resolveMcastHost(target addrconfig.HostTarget, ipv6 bool) (net.IP, error) {
	if target.IsLiteral() {
		if target.Literal.Is4() {
			ip := target.Literal.As4()
			return net.IP(ip[:]), nil
		}
		ip := target.Literal.As16()
		return net.IP(ip[:]), nil
	}
	field := strings.TrimSpace(target.Name)
	if field == "" {
		return nil, fmt.Errorf("bad group %q", field)
	}
	network := "ip4"
	if ipv6 {
		network = "ip6"
	}
	addr, err := net.ResolveIPAddr(network, field)
	if err != nil || addr == nil || addr.IP == nil {
		return nil, fmt.Errorf("bad group %q", field)
	}
	return addr.IP, nil
}

func resolveMcastIPv4Address(field string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip4", strings.TrimSpace(field))
	if err != nil || addr == nil || addr.IP.To4() == nil {
		return nil, fmt.Errorf("bad IPv4 address %q", field)
	}
	return addr.IP.To4(), nil
}

func resolveMcastInterfaceToken(token, optionName string) (uint32, bool, error) {
	if token == "" {
		return 0, false, nil
	}
	if idx, ok := parseClassicInterfaceIndex(token); ok {
		return idx, true, nil
	}
	ifi, err := net.InterfaceByName(token)
	if err != nil {
		return 0, false, fmt.Errorf("%s: interface %q: %w", optionName, token, err)
	}
	idx, ok := Uint32FromInt(ifi.Index)
	if !ok {
		return 0, false, fmt.Errorf("%s: interface %q index %d is out of range", optionName, token, ifi.Index)
	}
	return idx, true, nil
}

func resolveJoinInterface(req addrconfig.MulticastRequest, name string) (ifaceAddr net.IP, idx uint32, idxSet bool, err error) {
	if req.ThreeField {
		ifaceAddr, err = resolveMcastIPv4Address(req.InterfaceAddr.String())
		if err != nil {
			return nil, 0, false, fmt.Errorf("%s: bad interface address %q", name, req.InterfaceAddr.String())
		}
	}
	if req.InterfaceIsID {
		return ifaceAddr, req.InterfaceID, true, nil
	}
	if req.InterfaceName == "" {
		return ifaceAddr, 0, false, nil
	}
	ifi, nameErr := net.InterfaceByName(req.InterfaceName)
	if nameErr == nil {
		idx, ok := Uint32FromInt(ifi.Index)
		if !ok {
			return nil, 0, false, fmt.Errorf("%s: interface %q index %d is out of range", name, req.InterfaceName, ifi.Index)
		}
		return ifaceAddr, idx, true, nil
	}
	if req.Kind == addrconfig.MulticastJoinIPv4 && !req.ThreeField {
		if addr, addrErr := resolveMcastIPv4Address(req.InterfaceName); addrErr == nil {
			return addr, 0, false, nil
		}
	}
	return nil, 0, false, fmt.Errorf("%s: interface %q: %w", name, req.InterfaceName, nameErr)
}

func applyMembershipRequest(fd int, req addrconfig.MulticastRequest) error {
	name := req.Name
	ipv6 := req.Kind == addrconfig.MulticastJoinIPv6
	if name == "" {
		if ipv6 {
			name = "ipv6-join-group"
		} else {
			name = "ip-add-membership"
		}
	}
	group, err := resolveMcastHost(req.Group, ipv6)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !ipv6 && group.To4() == nil {
		return fmt.Errorf("%s: IPv4 membership requires an IPv4 group, got %s", name, group)
	}
	ifaceAddr, idx, idxSet, err := resolveJoinInterface(req, name)
	if err != nil {
		return err
	}
	if ipv6 {
		if !idxSet {
			return fmt.Errorf("%s: expected interface name or index", name)
		}
		return setIPv6MembershipFD(fd, group, idx)
	}
	return setIPv4MembershipFD(fd, group.To4(), ifaceAddr, idx, idxSet)
}

func applyMulticastNamedFD(fd int, name string, req addrconfig.MulticastRequest) error {
	switch req.Kind {
	case addrconfig.MulticastInterfaceIPv4:
		host := strings.TrimSpace(req.InterfaceAddr.String())
		if host == "" {
			return fmt.Errorf("%s: expected IPv4 hostname or address", name)
		}
		addr, err := resolveMcastIPv4Address(host)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		var ip4 [4]byte
		copy(ip4[:], addr.To4())
		if err := setSockoptInet4Addr(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, ip4); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case addrconfig.MulticastLoopIPv4, addrconfig.MulticastTTLIPv4:
		opt := unix.IP_MULTICAST_LOOP
		if req.Kind == addrconfig.MulticastTTLIPv4 {
			opt = unix.IP_MULTICAST_TTL
		}
		if err := setSockoptByte(fd, unix.IPPROTO_IP, opt, byte(req.Value)); err != nil { // #nosec G115 -- decoder bounds multicast loop/ttl
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case addrconfig.MulticastLoopIPv6:
		family, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		if family == ipFamilyV4 {
			return fmt.Errorf("%s: not supported on IPv4", name)
		}
		if err := setSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, req.Value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	default:
		return fmt.Errorf("%s: internal error", name)
	}
}

func parseClassicInterfaceIndex(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	// Reject Go-only 0b/0o prefixes and underscores; the token is a C-style
	// base-0 integer (decimal, octal, or hex).
	unsigned := s
	if unsigned[0] == '+' || unsigned[0] == '-' {
		unsigned = unsigned[1:]
	}
	if unsigned == "" || strings.ContainsRune(unsigned, '_') ||
		strings.HasPrefix(unsigned, "0b") || strings.HasPrefix(unsigned, "0B") ||
		strings.HasPrefix(unsigned, "0o") || strings.HasPrefix(unsigned, "0O") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 0, strconv.IntSize)
	if err != nil {
		return 0, false
	}
	// Assign the signed value to unsigned int, including negative values and
	// high-bit indices; the kernel accepts or rejects the result.
	return uint32(n), true // #nosec G115 -- signed-to-unsigned index conversion
}

func setIPv6MembershipFD(fd int, group net.IP, ifindex uint32) error {
	var mreq unix.IPv6Mreq
	copy(mreq.Multiaddr[:], group.To16())
	mreq.Interface = ifindex
	recordSockoptBytes(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, nil)
	if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq); err != nil {
		return fmt.Errorf("ipv6-join-group: %w", err)
	}
	return nil
}

func applyPreparedMulticast(fd int, req addrconfig.MulticastRequest) error {
	name := req.Name
	switch req.Kind {
	case addrconfig.MulticastJoinIPv4, addrconfig.MulticastJoinIPv6:
		return applyMembershipRequest(fd, req)
	case addrconfig.MulticastInterfaceIPv4:
		if name == "" {
			name = "ip-multicast-if"
		}
		return applyMulticastNamedFD(fd, name, req)
	case addrconfig.MulticastLoopIPv4:
		if name == "" {
			name = "ip-multicast-loop"
		}
		return applyMulticastNamedFD(fd, name, req)
	case addrconfig.MulticastTTLIPv4:
		if name == "" {
			name = "ip-multicast-ttl"
		}
		return applyMulticastNamedFD(fd, name, req)
	case addrconfig.MulticastLoopIPv6:
		if name == "" {
			name = "ipv6-multicast-loop"
		}
		return applyMulticastNamedFD(fd, name, req)
	default:
		return fmt.Errorf("%s: internal error", name)
	}
}

func applyPreparedSourceMulticast(fd int, req addrconfig.SourceMulticastRequest) error {
	name := req.Name
	if req.IPv6 {
		if name == "" {
			name = "ipv6-join-source-group"
		}
	} else if name == "" {
		name = "ip-add-source-membership"
	}
	group, err := resolveMcastHost(req.Group, req.IPv6)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	source, err := resolveMcastHost(req.Source, req.IPv6)
	if err != nil {
		return fmt.Errorf("%s: bad source %q", name, req.Source.String())
	}
	if !req.IPv6 {
		if group.To4() == nil {
			return fmt.Errorf("%s: IPv4 source membership requires an IPv4 group, got %s", name, group)
		}
		if source.To4() == nil {
			return fmt.Errorf("%s: IPv4 source membership requires an IPv4 source, got %s", name, source)
		}
		iface, err := resolveMcastIPv4Address(req.Interface.String())
		if err != nil {
			return fmt.Errorf("%s: bad interface address %q", name, req.Interface.String())
		}
		return setIPv4SourceMembershipFD(fd, group.To4(), iface, source.To4())
	}
	sockFamily, err := socketIPFamily(fd)
	if err != nil {
		return err
	}
	if sockFamily == ipFamilyV4 {
		return fmt.Errorf("%s: not supported on IPv4", name)
	}
	if group.To4() != nil {
		return fmt.Errorf("%s: IPv6 source membership requires an IPv6 group, got %s", name, group)
	}
	if source.To4() != nil {
		return fmt.Errorf("%s: IPv6 source membership requires an IPv6 source, got %s", name, source)
	}
	idx, idxSet, err := resolveMcastInterfaceToken(req.Interface.String(), name)
	if err != nil {
		return err
	}
	if !idxSet {
		return fmt.Errorf("%s: expected interface name or index", name)
	}
	return setIPv6SourceMembershipFD(fd, group, idx, source)
}
