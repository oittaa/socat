//go:build unix && !linux

package xio

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func setIPv4MembershipFD(fd int, group, ifaceAddr net.IP, ifindex uint32, idxSet bool) error {
	if ifaceAddr == nil && idxSet && ifindex != 0 {
		var err error
		ifaceAddr, err = ipv4AddressForInterfaceIndex(ifindex)
		if err != nil {
			return fmt.Errorf("ip-add-membership: %w", err)
		}
	}
	var mreq unix.IPMreq
	copy(mreq.Multiaddr[:], group.To4())
	if ifaceAddr != nil {
		copy(mreq.Interface[:], ifaceAddr.To4())
	}
	payload := make([]byte, 0, len(mreq.Multiaddr)+len(mreq.Interface))
	payload = append(payload, mreq.Multiaddr[:]...)
	payload = append(payload, mreq.Interface[:]...)
	recordSockoptBytes(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, payload)
	if err := unix.SetsockoptIPMreq(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}

func ipv4AddressForInterfaceIndex(ifindex uint32) (net.IP, error) {
	maxInt := uint64(^uint(0) >> 1)
	if uint64(ifindex) > maxInt {
		return nil, fmt.Errorf("interface index %d is out of range", ifindex)
	}
	ifi, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return nil, fmt.Errorf("interface index %d: %w", ifindex, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %q addresses: %w", ifi.Name, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPAddr:
			ip = v.IP
		case *net.IPNet:
			ip = v.IP
		default:
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("interface %q has no IPv4 address", ifi.Name)
}
