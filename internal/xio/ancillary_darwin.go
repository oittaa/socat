//go:build darwin

package xio

import (
	"net"

	"golang.org/x/sys/unix"
)

func ancillaryRecvSockoptPlatform(canonical string) (level, opt int, ok bool) {
	switch canonical {
	case "ip-recvdstaddr":
		return unix.IPPROTO_IP, unix.IP_RECVDSTADDR, true
	case "ip-recvif":
		return unix.IPPROTO_IP, unix.IP_RECVIF, true
	default:
		return 0, 0, false
	}
}

// handleIPv4CmsgBSD is classic xio-ip.c IP_RECVDSTADDR / IP_RECVIF
// (tag-1.8.1.3 12c08bf; official master af5388c is the same).
func handleIPv4CmsgBSD(typ int32, data []byte, g *Global) bool {
	switch typ {
	case unix.IP_RECVDSTADDR:
		if len(data) < 4 {
			return true
		}
		val := net.IP(data[:4]).String()
		logAncillary(g, "IP_RECVDSTADDR", "dstaddr", val)
		SetSessionEnv(g, "IP_DSTADDR", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("IP_RECVDSTADDR: %s", val)
		}
		return true
	case unix.IP_RECVIF:
		name, ok := sockaddrDLName(data)
		if !ok {
			return true
		}
		logAncillary(g, "IP_RECVIF", "if", name)
		SetSessionEnv(g, "IP_IF", name)
		if g != nil && g.Log != nil {
			g.Log.Noticef("IP_RECVIF: %s", name)
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
