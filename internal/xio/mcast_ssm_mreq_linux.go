//go:build linux

package xio

import (
	"net"

	"golang.org/x/sys/unix"
)

func setSockaddrInet6Len(*unix.RawSockaddrInet6) {}

// packIPMreqSource is Linux struct ip_mreq_source:
// imr_multiaddr, imr_interface, imr_sourceaddr (12 bytes).
// Classic xioapply_ip_add_source_membership (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a) fills those named fields.
func packIPMreqSource(group, iface, source net.IP) [12]byte {
	var mreq [12]byte
	copy(mreq[0:4], group.To4())
	copy(mreq[4:8], iface.To4())
	copy(mreq[8:12], source.To4())
	return mreq
}
