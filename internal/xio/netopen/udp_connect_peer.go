package netopen

import (
	"fmt"
	"math"
	"net"
)

// connectUDPPeer associates an already-bound UDP socket with peer, matching
// UDP-LISTEN connecting back to the sender so shutdown(SHUT_WR) is valid.
func connectUDPPeer(c *net.UDPConn, peer *net.UDPAddr) error {
	if c == nil || peer == nil {
		return net.ErrClosed
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cerr = connectUDPPeerFD(fd, peer)
	}); err != nil {
		return err
	}
	return cerr
}

func udpPeerIPv4Addr(peer *net.UDPAddr) ([4]byte, error) {
	var addr [4]byte
	if peer == nil {
		return addr, net.ErrClosed
	}
	ip4 := peer.IP.To4()
	if ip4 == nil {
		return addr, fmt.Errorf("UDP connect: IPv6 peer on IPv4 socket")
	}
	copy(addr[:], ip4)
	return addr, nil
}

func udpPeerIPv6Addr(peer *net.UDPAddr) ([16]byte, uint32, error) {
	var addr [16]byte
	if peer == nil {
		return addr, 0, net.ErrClosed
	}
	ip6 := peer.IP.To16()
	if ip6 == nil {
		return addr, 0, fmt.Errorf("UDP connect: invalid address %q", peer)
	}
	copy(addr[:], ip6)
	if peer.Zone == "" || peer.IP.To4() != nil {
		return addr, 0, nil
	}
	ifi, err := net.InterfaceByName(peer.Zone)
	if err != nil {
		return addr, 0, fmt.Errorf("UDP connect: zone %q: %w", peer.Zone, err)
	}
	if ifi.Index < 0 || ifi.Index > math.MaxUint32 {
		return addr, 0, fmt.Errorf("UDP connect: zone %q: interface index %d out of range", peer.Zone, ifi.Index)
	}
	return addr, uint32(ifi.Index), nil
}
