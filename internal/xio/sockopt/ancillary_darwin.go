//go:build darwin

package sockopt

import (
	"net"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

func ancillaryRecvSockoptPlatform(id addrconfig.AncillaryOption) (level, opt int, ok bool) {
	switch id {
	case addrconfig.AncillaryIPRecvDstAddr:
		return unix.IPPROTO_IP, unix.IP_RECVDSTADDR, true
	case addrconfig.AncillaryIPRecvIf:
		return unix.IPPROTO_IP, unix.IP_RECVIF, true
	default:
		return 0, 0, false
	}
}

// handleIPv4CmsgDarwin handles IP_RECVDSTADDR / IP_RECVIF.
func handleIPv4CmsgDarwin(typ int32, data []byte, g Session) bool {
	switch typ {
	case unix.IP_RECVDSTADDR:
		if len(data) < 4 {
			return true
		}
		val := net.IP(data[:4]).String()
		LogAncillary(g, "IP_RECVDSTADDR", "dstaddr", val)
		sessionSet(g, "IP_DSTADDR", val)
		if g != nil {
			g.Noticef("IP_RECVDSTADDR: %s", val)
		}
		return true
	case unix.IP_RECVIF:
		name, ok := sockaddrDLName(data)
		if !ok {
			return true
		}
		LogAncillary(g, "IP_RECVIF", "if", name)
		sessionSet(g, "IP_IF", name)
		if g != nil {
			g.Noticef("IP_RECVIF: %s", name)
		}
		return true
	default:
		return false
	}
}

// sockaddrDLName reads sdl_nlen bytes of sdl_data from a sockaddr_dl cmsg.
func sockaddrDLName(data []byte) (string, bool) {
	if len(data) < 8 {
		return "", false
	}
	nlen := int(data[5])
	if nlen <= 0 || 8+nlen > len(data) {
		return "", false
	}
	return string(data[8 : 8+nlen]), true
}
