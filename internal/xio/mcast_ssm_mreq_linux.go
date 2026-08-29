//go:build linux

package xio

import (
	"net"

	"golang.org/x/sys/unix"
)

func setSockaddrInet6Len(*unix.RawSockaddrInet6) {}

// packIPMreqSource is Linux struct ip_mreq_source:
// imr_multiaddr, imr_interface, imr_sourceaddr (12 bytes).
func packIPMreqSource(group, iface, source net.IP) [12]byte {
	var mreq [12]byte
	copy(mreq[0:4], group.To4())
	copy(mreq[4:8], iface.To4())
	copy(mreq[8:12], source.To4())
	return mreq
}
