//go:build linux

package xio

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

const maxRecvErrQueue = 32

func recvErrSupported() bool { return true }

func applyRecvErrSockopt(fd int, o parse.Option) error {
	n, err := ancillaryRecvOptionInt(o)
	if err != nil {
		return fmt.Errorf("ip-recverr: %w", err)
	}
	if err := setSockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, n); err != nil {
		return fmt.Errorf("ip-recverr: %w", err)
	}
	return nil
}

// DrainRecvErrFromConn reads MSG_ERRQUEUE without delivering payload as data.
func DrainRecvErrFromConn(c syscall.Conn, g *Global) {
	drainRecvErrFromConn(c, g)
}

func drainRecvErrFromConn(c syscall.Conn, g *Global) {
	if c == nil {
		return
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		drainRecvErrQueue(int(fd), g)
	})
}

func drainRecvErrQueue(fd int, g *Global) {
	var buf [256]byte
	var oob [512]byte
	for i := 0; i < maxRecvErrQueue; i++ {
		n, oobn, _, _, err := unix.Recvmsg(fd, buf[:], oob[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return
		}
		_ = n // error-queue payload is the original packet, never user data
		if oobn > 0 {
			processRecvErrOOB(oob[:oobn], g)
		}
	}
}

func processRecvErrOOB(oob []byte, g *Global) {
	if len(oob) == 0 {
		return
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if m.Header.Type != unix.IP_RECVERR {
			continue
		}
		if m.Header.Level != unix.SOL_IP && m.Header.Level != unix.IPPROTO_IP {
			continue
		}
		handleIPRecvErrCmsg(m.Data, g)
	}
}

func handleIPRecvErrCmsg(data []byte, g *Global) {
	if len(data) < 16 {
		return
	}
	errno := binary.NativeEndian.Uint32(data[0:4])
	origin := data[4]
	typ := data[5]
	code := data[6]
	info := binary.NativeEndian.Uint32(data[8:12])
	eeData := binary.NativeEndian.Uint32(data[12:16])
	errnoStr := fmt.Sprintf("%d", errno)
	originStr := fmt.Sprintf("%d", origin)
	typeStr := fmt.Sprintf("%d", typ)
	codeStr := fmt.Sprintf("%d", code)
	infoStr := fmt.Sprintf("%d", info)
	dataStr := fmt.Sprintf("%d", eeData)
	logAncillary(g, "IP_RECVERR", "errno", errnoStr)
	logAncillary(g, "IP_RECVERR", "origin", originStr)
	logAncillary(g, "IP_RECVERR", "type", typeStr)
	logAncillary(g, "IP_RECVERR", "code", codeStr)
	logAncillary(g, "IP_RECVERR", "info", infoStr)
	logAncillary(g, "IP_RECVERR", "data", dataStr)
	SetSessionEnv(g, "IP_RECVERR_ERRNO", errnoStr)
	SetSessionEnv(g, "IP_RECVERR_ORIGIN", originStr)
	SetSessionEnv(g, "IP_RECVERR_TYPE", typeStr)
	SetSessionEnv(g, "IP_RECVERR_CODE", codeStr)
	SetSessionEnv(g, "IP_RECVERR_INFO", infoStr)
	SetSessionEnv(g, "IP_RECVERR_DATA", dataStr)
	if g == nil || g.Log == nil {
		return
	}
	switch origin {
	case unix.SO_EE_ORIGIN_ICMP:
		addr := recverrOffenderIPv4(data)
		g.Log.Noticef("received ICMP from %s, type %d, code %d, info %d, data %d, resulting in errno %d",
			addr, typ, code, info, eeData, errno)
	case unix.SO_EE_ORIGIN_ICMP6:
		g.Log.Noticef("received ICMP type %d, code %d, info %d, data %d, resulting in errno %d",
			typ, code, info, eeData, errno)
	default:
		g.Log.Noticef("received error message origin %d, type %d, code %d, info %d, data %d, generating errno %d",
			origin, typ, code, info, eeData, errno)
	}
}

func recverrOffenderIPv4(data []byte) string {
	// sock_extended_err is followed by the offender sockaddr (SO_EE_OFFENDER).
	if len(data) < 16+8 {
		return "0.0.0.0"
	}
	family := binary.NativeEndian.Uint16(data[16:18])
	if family != unix.AF_INET || len(data) < 16+8 {
		return "0.0.0.0"
	}
	return net.IP(data[20:24]).String()
}
