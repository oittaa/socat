//go:build unix

package xio

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// parseMcastSpec parses classic ip-add-membership / ipv6-join-group:
// "224.x.x.x:iface", "[ff02::2]:iface", or "group%iface".
func parseMcastSpec(spec, optionName string) (net.IP, string, error) {
	if optionName == "" {
		optionName = "ip-add-membership"
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, "", fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
	}
	if strings.HasPrefix(spec, "[") {
		end := strings.IndexByte(spec, ']')
		if end < 0 {
			return nil, "", fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
		}
		gip := net.ParseIP(spec[1:end])
		if gip == nil {
			return nil, "", fmt.Errorf("%s: bad group %q", optionName, spec[1:end])
		}
		rest := spec[end+1:]
		if strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "%") {
			rest = rest[1:]
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return nil, "", fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
		}
		return gip, rest, nil
	}
	mcast, iface, ok := strings.Cut(spec, ":")
	if !ok {
		mcast, iface, ok = strings.Cut(spec, "%")
	}
	if !ok || strings.Count(spec, ":") > 1 {
		// Unbracketed IPv6: last colon separates iface.
		if i := strings.LastIndex(spec, ":"); i > 0 {
			if g := net.ParseIP(spec[:i]); g != nil {
				return g, strings.TrimSpace(spec[i+1:]), nil
			}
		}
		if !ok {
			return nil, "", fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
		}
	}
	gip := net.ParseIP(strings.TrimSpace(mcast))
	if gip == nil {
		return nil, "", fmt.Errorf("%s: bad group %q", optionName, mcast)
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, "", fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
	}
	return gip, iface, nil
}

func applyMembershipJoins(fd int, joins []membershipJoin) error {
	for _, join := range joins {
		if err := joinMulticastFD(fd, join); err != nil {
			return err
		}
	}
	return nil
}

func joinMulticastFD(fd int, join membershipJoin) error {
	name := join.optionName()
	gip, iface, err := parseMcastSpec(join.spec, name)
	if err != nil {
		return err
	}
	if join.family == membershipFamilyIPv4 && gip.To4() == nil {
		return fmt.Errorf("%s: IPv4 membership requires an IPv4 group, got %s", name, gip)
	}
	var ifi *net.Interface
	iface = strings.TrimSpace(iface)
	if ip := net.ParseIP(iface); ip != nil {
		ifaces, _ := net.Interfaces()
		for i := range ifaces {
			cand := &ifaces[i]
			addrs, _ := cand.Addrs()
			for _, a := range addrs {
				var ipn net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ipn = v.IP
				case *net.IPAddr:
					ipn = v.IP
				}
				if ipn != nil && ipn.Equal(ip) {
					ifi = cand
					break
				}
			}
			if ifi != nil {
				break
			}
		}
		if join.family == membershipFamilyIPv4 && gip.To4() != nil && ip.To4() != nil {
			return setIPv4MembershipFD(fd, gip.To4(), ip.To4())
		}
	} else {
		ifi, err = net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("%s: interface %q: %w", name, iface, err)
		}
	}
	if join.family == membershipFamilyIPv4 {
		var ifaceIP net.IP
		if ifi != nil {
			addrs, _ := ifi.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					ifaceIP = ipn.IP.To4()
					break
				}
			}
		}
		if ifaceIP == nil {
			ifaceIP = net.IPv4zero.To4()
		}
		return setIPv4MembershipFD(fd, gip.To4(), ifaceIP)
	}
	return setIPv6MembershipFD(fd, gip, ifi)
}

func setIPv4MembershipFD(fd int, group, ifaceIP net.IP) error {
	var mreq unix.IPMreq
	copy(mreq.Multiaddr[:], group.To4())
	copy(mreq.Interface[:], ifaceIP.To4())
	if err := unix.SetsockoptIPMreq(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}

func setIPv6MembershipFD(fd int, group net.IP, ifi *net.Interface) error {
	idx := 0
	if ifi != nil {
		idx = ifi.Index
	}
	ifi32, ok := Uint32FromInt(idx)
	if !ok {
		return fmt.Errorf("ipv6-join-group: interface index %d out of range", idx)
	}
	var mreq unix.IPv6Mreq
	copy(mreq.Multiaddr[:], group.To16())
	mreq.Interface = ifi32
	if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq); err != nil {
		return fmt.Errorf("ipv6-join-group: %w", err)
	}
	return nil
}
