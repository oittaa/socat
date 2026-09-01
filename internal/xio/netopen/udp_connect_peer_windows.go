//go:build windows

package netopen

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

func connectUDPPeerFD(fd uintptr, peer *net.UDPAddr) error {
	sa, err := udpPeerSockaddr(windows.Handle(fd), peer)
	if err != nil {
		return err
	}
	return windows.Connect(windows.Handle(fd), sa)
}

func udpPeerSockaddr(fd windows.Handle, peer *net.UDPAddr) (windows.Sockaddr, error) {
	if peer == nil {
		return nil, net.ErrClosed
	}
	local, err := windows.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	switch local.(type) {
	case *windows.SockaddrInet6:
		addr, zone, err := udpPeerIPv6Addr(peer)
		if err != nil {
			return nil, err
		}
		return &windows.SockaddrInet6{Port: peer.Port, Addr: addr, ZoneId: zone}, nil
	case *windows.SockaddrInet4:
		addr, err := udpPeerIPv4Addr(peer)
		if err != nil {
			return nil, err
		}
		return &windows.SockaddrInet4{Port: peer.Port, Addr: addr}, nil
	default:
		return nil, fmt.Errorf("UDP connect: unsupported address family")
	}
}
