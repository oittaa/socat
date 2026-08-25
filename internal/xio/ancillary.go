//go:build unix

package xio

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// NeedAncillary reports whether the address requests control messages on recv.
func NeedAncillary(s parse.Spec) bool {
	for _, name := range []string{
		"so-timestamp", "timestamp",
		"ip-pktinfo", "pktinfo",
		"ip-recvttl", "recvttl",
		"ip-recvtos", "recvtos",
		"ip-recvopts", "recvopts",
		"ipv6-recvpktinfo", "recvpktinfo",
		"ipv6-recvhoplimit", "recvhoplimit",
		"ipv6-recvtclass", "recvtclass",
	} {
		if s.BoolOption(name) {
			return true
		}
	}
	return false
}

// ApplyAncillaryRecvOpts enables kernel delivery of control messages on fd.
func ApplyAncillaryRecvOpts(fd int, s parse.Spec) error {
	on := func(name string) bool {
		return s.BoolOption(name)
	}
	set := func(name string, level, option int) error {
		if err := unix.SetsockoptInt(fd, level, option, 1); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	if on("so-timestamp") || on("timestamp") {
		if err := set("so-timestamp", unix.SOL_SOCKET, unix.SO_TIMESTAMP); err != nil {
			return err
		}
	}
	if on("ip-pktinfo") || on("pktinfo") {
		if err := set("ip-pktinfo", unix.IPPROTO_IP, unix.IP_PKTINFO); err != nil {
			return err
		}
	}
	if on("ip-recvttl") || on("recvttl") {
		if err := set("ip-recvttl", unix.IPPROTO_IP, unix.IP_RECVTTL); err != nil {
			return err
		}
	}
	if on("ip-recvtos") || on("recvtos") {
		if err := set("ip-recvtos", unix.IPPROTO_IP, unix.IP_RECVTOS); err != nil {
			return err
		}
	}
	if on("ip-recvopts") || on("recvopts") {
		if err := set("ip-recvopts", unix.IPPROTO_IP, unix.IP_RECVOPTS); err != nil {
			return err
		}
	}
	if on("ipv6-recvpktinfo") || on("recvpktinfo") {
		if err := set("ipv6-recvpktinfo", unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO); err != nil {
			return err
		}
	}
	if on("ipv6-recvhoplimit") || on("recvhoplimit") {
		if err := set("ipv6-recvhoplimit", unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT); err != nil {
			return err
		}
	}
	if on("ipv6-recvtclass") || on("recvtclass") {
		if err := set("ipv6-recvtclass", unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS); err != nil {
			return err
		}
	}
	return nil
}

// ApplyIPSendOpts sets classic send-side IP options on a UDP/IP socket.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	if v := s.OptionValue("ip-ttl", ""); v != "" {
		n, err := ParseIntAny(v)
		if err != nil {
			return fmt.Errorf("ip-ttl: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, n); err != nil {
			return fmt.Errorf("ip-ttl: %w", err)
		}
	} else if v := s.OptionValue("ttl", ""); v != "" {
		n, err := ParseIntAny(v)
		if err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, n); err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
	}
	if v := s.OptionValue("ip-tos", ""); v != "" {
		n, err := ParseIntAny(v)
		if err != nil {
			return fmt.Errorf("ip-tos: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, n); err != nil {
			return fmt.Errorf("ip-tos: %w", err)
		}
	} else if v := s.OptionValue("tos", ""); v != "" {
		n, err := ParseIntAny(v)
		if err != nil {
			return fmt.Errorf("tos: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, n); err != nil {
			return fmt.Errorf("tos: %w", err)
		}
	}
	if v := s.OptionValue("ip-options", ""); v != "" {
		// classic ip-options=x01000000 hex dump of IP options bytes
		b, err := ParseHexOpt(v)
		if err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
		if len(b) == 0 {
			return fmt.Errorf("ip-options: empty value")
		}
		if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(b)); err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
	}
	if strings.Contains(network, "6") {
		if v := s.OptionValue("ipv6-unicast-hops", ""); v != "" {
			n, err := ParseIntAny(v)
			if err != nil {
				return fmt.Errorf("ipv6-unicast-hops: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, n); err != nil {
				return fmt.Errorf("ipv6-unicast-hops: %w", err)
			}
		} else if v := s.OptionValue("unicast-hops", ""); v != "" {
			n, err := ParseIntAny(v)
			if err != nil {
				return fmt.Errorf("unicast-hops: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, n); err != nil {
				return fmt.Errorf("unicast-hops: %w", err)
			}
		}
		if v := s.OptionValue("ipv6-tclass", ""); v != "" {
			n, err := ParseIntAny(v)
			if err != nil {
				return fmt.Errorf("ipv6-tclass: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n); err != nil {
				return fmt.Errorf("ipv6-tclass: %w", err)
			}
		} else if v := s.OptionValue("tclass", ""); v != "" {
			n, err := ParseIntAny(v)
			if err != nil {
				return fmt.Errorf("tclass: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n); err != nil {
				return fmt.Errorf("tclass: %w", err)
			}
		}
	}
	return nil
}

func ParseHexOpt(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "x") || strings.HasPrefix(v, "X") {
		v = v[1:]
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		v = v[2:]
	}
	return hex.DecodeString(v)
}

// ProcessAncillary parses oob from recvmsg, logs classic Info lines, and sets
// process env SOCAT_* / PROGNAME_* for SYSTEM children.
func ProcessAncillary(oob []byte, g *Global) {
	if len(oob) == 0 {
		return
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		switch m.Header.Level {
		case unix.SOL_SOCKET:
			// Linux delivers SO_TIMESTAMP; classic logs as SCM_TIMESTAMP.
			if m.Header.Type == unix.SO_TIMESTAMP || m.Header.Type == unix.SCM_TIMESTAMP {
				handleTimestamp(m.Data, g)
			}
		case unix.IPPROTO_IP: // == SOL_IP on Linux
			handleIPv4Cmsg(m.Header.Type, m.Data, g)
		case unix.IPPROTO_IPV6:
			handleIPv6Cmsg(m.Header.Type, m.Data, g)
		}
	}
}

func handleTimestamp(data []byte, g *Global) {
	sec, usec, ok := parseCmsgTimeval(data)
	if !ok {
		return
	}
	t := time.Unix(sec, usec*1000)
	// Classic ctime_r style: "Mon Jan  2 15:04:05 2006, 000123 usecs"
	val := t.Format("Mon Jan _2 15:04:05 2006") + fmt.Sprintf(", %06d usecs", usec)
	logAncillary(g, "SCM_TIMESTAMP", "timestamp", val)
	SetSessionEnv(g, "TIMESTAMP", val)
}

// parseCmsgTimeval reads a kernel timeval from cmsg data (native endian).
// 16-byte form is two 64-bit fields (Linux 64-bit) or int64+int32+pad (Darwin).
func parseCmsgTimeval(data []byte) (sec, usec int64, ok bool) {
	switch {
	case len(data) >= 16:
		var ok1, ok2 bool
		sec, ok1 = Int64FromUint64(binary.NativeEndian.Uint64(data[0:8]))
		usec, ok2 = Int64FromUint64(binary.NativeEndian.Uint64(data[8:16]))
		if !ok1 {
			return 0, 0, false
		}
		if !ok2 || usec < 0 || usec >= 1_000_000 {
			u32, ok3 := Int32FromUint32(binary.NativeEndian.Uint32(data[8:12]))
			if !ok3 {
				return 0, 0, false
			}
			usec = int64(u32)
		}
		return sec, usec, true
	case len(data) >= 8:
		s32, ok1 := Int32FromUint32(binary.NativeEndian.Uint32(data[0:4]))
		u32, ok2 := Int32FromUint32(binary.NativeEndian.Uint32(data[4:8]))
		if !ok1 || !ok2 {
			return 0, 0, false
		}
		return int64(s32), int64(u32), true
	default:
		return 0, 0, false
	}
}

func parseInet4Pktinfo(data []byte) (ifindex int, specDst, addr net.IP, ok bool) {
	if len(data) < unix.SizeofInet4Pktinfo {
		return 0, nil, nil, false
	}
	ifi32, ok := Int32FromUint32(binary.NativeEndian.Uint32(data[0:4]))
	if !ok {
		return 0, nil, nil, false
	}
	ifindex = int(ifi32)
	specDst = net.IP(data[4:8])
	addr = net.IP(data[8:12])
	return ifindex, specDst, addr, true
}

func parseInet6Pktinfo(data []byte) (ifindex int, addr net.IP, ok bool) {
	if len(data) < unix.SizeofInet6Pktinfo {
		return 0, nil, false
	}
	addr = net.IP(data[0:16])
	ifindex = int(binary.NativeEndian.Uint32(data[16:20]))
	return ifindex, addr, true
}

// cmsgInt extracts an int-sized control value (1 or 4 bytes, host endian).
func cmsgInt(data []byte) int {
	switch {
	case len(data) >= 4:
		v, ok := Int32FromUint32(binary.NativeEndian.Uint32(data[:4]))
		if !ok {
			return 0
		}
		return int(v)
	case len(data) >= 1:
		return int(data[0])
	default:
		return 0
	}
}

func handleIPv4Cmsg(typ int32, data []byte, g *Global) {
	switch typ {
	case unix.IP_TTL:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IP_TTL", "ttl", val)
		SetSessionEnv(g, "IP_TTL", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: ttl=%s", val)
		}
	case unix.IP_TOS:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IP_TOS", "tos", val)
		SetSessionEnv(g, "IP_TOS", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: tos=%s", val)
		}
	case unix.IP_PKTINFO:
		ifi, specDst, dstIP, ok := parseInet4Pktinfo(data)
		if !ok {
			return
		}
		ifname := ifIndexName(ifi)
		loc := specDst.String()
		dst := dstIP.String()
		logAncillary(g, "IP_PKTINFO", "if", ifname)
		logAncillary(g, "IP_PKTINFO", "locaddr", loc)
		logAncillary(g, "IP_PKTINFO", "dstaddr", dst)
		SetSessionEnv(g, "IP_IF", ifname)
		SetSessionEnv(g, "IP_LOCADDR", loc)
		SetSessionEnv(g, "IP_DSTADDR", dst)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: interface %q, locaddr=%s, dstaddr=%s", ifname, loc, dst)
		}
	case unix.IP_OPTIONS, unix.IP_RECVOPTS:
		// Linux delivers received IP options as cmsg type IP_RECVOPTS (6).
		// classic xiodump: x + lowercase hex of option bytes
		val := "x" + fmt.Sprintf("%x", data)
		logAncillary(g, "IP_OPTIONS", "options", val)
		SetSessionEnv(g, "IP_OPTIONS", val)
	}
}

func handleIPv6Cmsg(typ int32, data []byte, g *Global) {
	switch typ {
	case unix.IPV6_PKTINFO:
		ifi, addr, ok := parseInet6Pktinfo(data)
		if !ok {
			return
		}
		dst := ExpandIPv6Full(addr)
		// Classic: [0000:0000:...:0001]
		br := "[" + dst + "]"
		ifname := ifIndexName(ifi)
		logAncillary(g, "IPV6_PKTINFO", "dstaddr", br)
		logAncillary(g, "IPV6_PKTINFO", "if", ifname)
		SetSessionEnv(g, "IPV6_DSTADDR", br)
		SetSessionEnv(g, "IPV6_IF", ifname)
	case unix.IPV6_HOPLIMIT:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IPV6_HOPLIMIT", "hoplimit", val)
		// classic: empty env name → falls back to type name
		SetSessionEnv(g, "IPV6_HOPLIMIT", val)
	case unix.IPV6_TCLASS:
		n := cmsgInt(data)
		u, ok := Uint32FromInt(n)
		if !ok {
			return
		}
		// classic: xiodump after ntohl → x000000aa style of the int value
		val := fmt.Sprintf("x%08x", u)
		logAncillary(g, "IPV6_TCLASS", "tclass", val)
		SetSessionEnv(g, "IPV6_TCLASS", val)
	}
}

func logAncillary(g *Global, typ, name, val string) {
	if g != nil && g.Log != nil {
		// Classic Info3("ancillary message: %s: %s=%s", ...)
		g.Log.Infof("ancillary message: %s: %s=%s", typ, name, val)
	}
}

func ifIndexName(idx int) string {
	if idx <= 0 {
		return ""
	}
	ifi, err := net.InterfaceByIndex(idx)
	if err != nil {
		return strconv.Itoa(idx)
	}
	return ifi.Name
}

// ExpandIPv6Full prints full zero-padded IPv6 (classic SCM/ENV form).
func ExpandIPv6Full(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// ReadUDPMsg reads one datagram with control messages when needed.
func ReadUDPMsg(c *net.UDPConn, p []byte, wantCtrl bool) (n int, oob []byte, addr *net.UDPAddr, err error) {
	if !wantCtrl {
		n, addr, err = c.ReadFromUDP(p)
		return n, nil, addr, err
	}
	oob = make([]byte, 1024)
	var oobn int
	n, oobn, _, addr, err = c.ReadMsgUDP(p, oob)
	if err != nil {
		return n, nil, nil, err
	}
	return n, oob[:oobn], addr, nil
}

// ApplyUDPConnOpts applies ancillary + send IP options on a live UDPConn.
func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, network string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		if err := ApplyAncillaryRecvOpts(int(fd), s); err != nil {
			optionErr = err
			return
		}
		optionErr = ApplyIPSendOpts(int(fd), s, network)
		if optionErr == nil {
			optionErr = ApplySocketOptions(int(fd), s)
		}
	})
	return errors.Join(controlErr, optionErr)
}
