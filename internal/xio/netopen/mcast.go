//go:build unix

package netopen

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// parseMcastSpec parses classic ip-add-membership / ipv6-join-group:
// "224.x.x.x:iface", "[ff02::2]:iface", or "group%iface".
func parseMcastSpec(spec string) (net.IP, string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, "", fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
	}
	if strings.HasPrefix(spec, "[") {
		end := strings.IndexByte(spec, ']')
		if end < 0 {
			return nil, "", fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
		}
		gip := net.ParseIP(spec[1:end])
		if gip == nil {
			return nil, "", fmt.Errorf("ip-add-membership: bad group %q", spec[1:end])
		}
		rest := spec[end+1:]
		if strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "%") {
			rest = rest[1:]
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return nil, "", fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
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
			return nil, "", fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
		}
	}
	gip := net.ParseIP(strings.TrimSpace(mcast))
	if gip == nil {
		return nil, "", fmt.Errorf("ip-add-membership: bad group %q", mcast)
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, "", fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
	}
	return gip, iface, nil
}

func joinMulticast(c syscallConn, spec string) error {
	gip, iface, err := parseMcastSpec(spec)
	if err != nil {
		return err
	}
	var ifi *net.Interface
	iface = strings.TrimSpace(iface)
	if ip := net.ParseIP(iface); ip != nil {
		ifaces, _ := net.Interfaces()
		for _, cand := range ifaces {
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
					ifi = &cand
					break
				}
			}
			if ifi != nil {
				break
			}
		}
		if gip.To4() != nil && ip.To4() != nil {
			return setIPv4Membership(c, gip.To4(), ip.To4())
		}
	} else {
		var err error
		ifi, err = net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("ip-add-membership: interface %q: %w", iface, err)
		}
	}
	if gip.To4() != nil {
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
		return setIPv4Membership(c, gip.To4(), ifaceIP)
	}
	return setIPv6Membership(c, gip, ifi)
}

func setIPv4Membership(c syscallConn, group, ifaceIP net.IP) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		var mreq unix.IPMreq
		copy(mreq.Multiaddr[:], group.To4())
		copy(mreq.Interface[:], ifaceIP.To4())
		serr = unix.SetsockoptIPMreq(int(fd), unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq)
	})
	if err != nil {
		return err
	}
	return serr
}

func setIPv6Membership(c syscallConn, group net.IP, ifi *net.Interface) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	idx := 0
	if ifi != nil {
		idx = ifi.Index
	}
	err = raw.Control(func(fd uintptr) {
		var mreq unix.IPv6Mreq
		copy(mreq.Multiaddr[:], group.To16())
		ifi32, ok := xio.Uint32FromInt(idx)
		if !ok {
			serr = fmt.Errorf("ipv6 join: interface index %d out of range", idx)
			return
		}
		mreq.Interface = ifi32
		serr = unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq)
	})
	if err != nil {
		return err
	}
	return serr
}
