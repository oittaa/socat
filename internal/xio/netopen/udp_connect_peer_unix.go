//go:build linux || darwin

package netopen

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func connectUDPPeerFD(fd uintptr, peer *net.UDPAddr) error {
	sa, err := udpPeerSockaddr(int(fd), peer)
	if err != nil {
		return err
	}
	return unix.Connect(int(fd), sa)
}

func udpPeerSockaddr(fd int, peer *net.UDPAddr) (unix.Sockaddr, error) {
	if peer == nil {
		return nil, net.ErrClosed
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	switch local.(type) {
	case *unix.SockaddrInet6:
		addr, zone, err := udpPeerIPv6Addr(peer)
		if err != nil {
			return nil, err
		}
		return &unix.SockaddrInet6{Port: peer.Port, Addr: addr, ZoneId: zone}, nil
	case *unix.SockaddrInet4:
		addr, err := udpPeerIPv4Addr(peer)
		if err != nil {
			return nil, err
		}
		return &unix.SockaddrInet4{Port: peer.Port, Addr: addr}, nil
	default:
		return nil, fmt.Errorf("UDP connect: unsupported address family")
	}
}
