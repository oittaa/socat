//go:build windows

package netopen

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

func connectUDPPeerFD(fd uintptr, peer *net.UDPAddr) error {
	sa, err := udpPeerSockaddr(peer)
	if err != nil {
		return err
	}
	return windows.Connect(windows.Handle(fd), sa)
}

func udpPeerSockaddr(peer *net.UDPAddr) (windows.Sockaddr, error) {
	if peer == nil {
		return nil, net.ErrClosed
	}
	if ip4 := peer.IP.To4(); ip4 != nil {
		sa := &windows.SockaddrInet4{Port: peer.Port}
		copy(sa.Addr[:], ip4)
		return sa, nil
	}
	ip6 := peer.IP.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("UDP connect: invalid address %q", peer)
	}
	sa := &windows.SockaddrInet6{Port: peer.Port}
	copy(sa.Addr[:], ip6)
	if peer.Zone != "" {
		ifi, err := net.InterfaceByName(peer.Zone)
		if err != nil {
			return nil, fmt.Errorf("UDP connect: zone %q: %w", peer.Zone, err)
		}
		sa.ZoneId = uint32(ifi.Index) // #nosec G115 -- kernel ifindex is non-negative
	}
	return sa, nil
}
