//go:build darwin || freebsd

package xio

import "net"

// packIPMreqSource is Darwin/FreeBSD struct ip_mreq_source:
// imr_multiaddr, imr_sourceaddr, imr_interface (12 bytes). Linux swaps
// the last two fields. Silent field-swap would join the wrong source.
func packIPMreqSource(group, iface, source net.IP) [12]byte {
	var mreq [12]byte
	copy(mreq[0:4], group.To4())
	copy(mreq[4:8], source.To4())
	copy(mreq[8:12], iface.To4())
	return mreq
}
