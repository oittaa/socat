package xio

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

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
		if s.HasOption(name) || s.BoolOption(name) {
			return true
		}
	}
	return false
}

// ApplyAncillaryRecvOpts enables kernel delivery of control messages on fd.
func ApplyAncillaryRecvOpts(fd int, s parse.Spec) {
	on := func(name string) bool {
		return s.HasOption(name) || s.BoolOption(name)
	}
	if on("so-timestamp") || on("timestamp") {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1)
	}
	if on("ip-pktinfo") || on("pktinfo") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}
	if on("ip-recvttl") || on("recvttl") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
	}
	if on("ip-recvtos") || on("recvtos") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
	}
	if on("ip-recvopts") || on("recvopts") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVOPTS, 1)
	}
	if on("ipv6-recvpktinfo") || on("recvpktinfo") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	}
	if on("ipv6-recvhoplimit") || on("recvhoplimit") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	}
	if on("ipv6-recvtclass") || on("recvtclass") {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
	}
}

// ApplyIPSendOpts sets classic send-side IP options on a UDP/IP socket.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) {
	if v := s.OptionValue("ip-ttl", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, n)
		}
	} else if v := s.OptionValue("ttl", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, n)
		}
	}
	if v := s.OptionValue("ip-tos", ""); v != "" {
		if n, err := ParseIntAny(v); err == nil {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, n)
		}
	} else if v := s.OptionValue("tos", ""); v != "" {
		if n, err := ParseIntAny(v); err == nil {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, n)
		}
	}
	if v := s.OptionValue("ip-options", ""); v != "" {
		// classic ip-options=x01000000 hex dump of IP options bytes
		if b, err := ParseHexOpt(v); err == nil && len(b) > 0 {
			_ = unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(b))
		}
	}
	if strings.Contains(network, "6") {
		if v := s.OptionValue("ipv6-unicast-hops", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, n)
			}
		} else if v := s.OptionValue("unicast-hops", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, n)
			}
		}
		if v := s.OptionValue("ipv6-tclass", ""); v != "" {
			if n, err := ParseIntAny(v); err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n)
			}
		} else if v := s.OptionValue("tclass", ""); v != "" {
			if n, err := ParseIntAny(v); err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n)
			}
		}
	}
}

func ParseIntAny(v string) (int, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, err := strconv.ParseUint(v[2:], 16, 32)
		return int(n), err
	}
	return strconv.Atoi(v)
}

func ParseHexOpt(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "x") || strings.HasPrefix(v, "X") {
		v = v[1:]
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		v = v[2:]
	}
	if len(v)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(v)/2)
	for i := 0; i < len(out); i++ {
		n, err := strconv.ParseUint(v[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(n)
	}
	return out, nil
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
	if len(data) < int(unsafe.Sizeof(unix.Timeval{})) {
		return
	}
	tv := (*unix.Timeval)(unsafe.Pointer(&data[0]))
	t := time.Unix(int64(tv.Sec), int64(tv.Usec)*1000)
	// Classic ctime_r style: "Mon Jan  2 15:04:05 2006, 000123 usecs"
	val := t.Format("Mon Jan _2 15:04:05 2006") + fmt.Sprintf(", %06d usecs", tv.Usec)
	logAncillary(g, "SCM_TIMESTAMP", "timestamp", val)
	setAncillaryEnv(g, "TIMESTAMP", val)
}

// cmsgInt extracts an int-sized control value (1 or 4 bytes, host endian).
func cmsgInt(data []byte) int {
	switch {
	case len(data) >= 4:
		return int(int32(binary.NativeEndian.Uint32(data[:4])))
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
		setAncillaryEnv(g, "IP_TTL", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: ttl=%s", val)
		}
	case unix.IP_TOS:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IP_TOS", "tos", val)
		setAncillaryEnv(g, "IP_TOS", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: tos=%s", val)
		}
	case unix.IP_PKTINFO:
		if len(data) < unix.SizeofInet4Pktinfo {
			return
		}
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
		ifname := ifIndexName(int(info.Ifindex))
		loc := net.IP(info.Spec_dst[:]).String()
		dst := net.IP(info.Addr[:]).String()
		logAncillary(g, "IP_PKTINFO", "if", ifname)
		logAncillary(g, "IP_PKTINFO", "locaddr", loc)
		logAncillary(g, "IP_PKTINFO", "dstaddr", dst)
		setAncillaryEnv(g, "IP_IF", ifname)
		setAncillaryEnv(g, "IP_LOCADDR", loc)
		setAncillaryEnv(g, "IP_DSTADDR", dst)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: interface %q, locaddr=%s, dstaddr=%s", ifname, loc, dst)
		}
	case unix.IP_OPTIONS, unix.IP_RECVOPTS:
		// Linux delivers received IP options as cmsg type IP_RECVOPTS (6).
		// classic xiodump: x + lowercase hex of option bytes
		val := "x" + fmt.Sprintf("%x", data)
		logAncillary(g, "IP_OPTIONS", "options", val)
		setAncillaryEnv(g, "IP_OPTIONS", val)
	}
}

func handleIPv6Cmsg(typ int32, data []byte, g *Global) {
	switch typ {
	case unix.IPV6_PKTINFO:
		if len(data) < unix.SizeofInet6Pktinfo {
			return
		}
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0]))
		dst := ExpandIPv6Full(net.IP(info.Addr[:]))
		// Classic: [0000:0000:...:0001]
		br := "[" + dst + "]"
		ifname := ifIndexName(int(info.Ifindex))
		logAncillary(g, "IPV6_PKTINFO", "dstaddr", br)
		logAncillary(g, "IPV6_PKTINFO", "if", ifname)
		setAncillaryEnv(g, "IPV6_DSTADDR", br)
		setAncillaryEnv(g, "IPV6_IF", ifname)
	case unix.IPV6_HOPLIMIT:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IPV6_HOPLIMIT", "hoplimit", val)
		// classic: empty env name → falls back to type name
		setAncillaryEnv(g, "IPV6_HOPLIMIT", val)
	case unix.IPV6_TCLASS:
		n := cmsgInt(data)
		// classic: xiodump after ntohl → x000000aa style of the int value
		val := fmt.Sprintf("x%08x", uint32(n)&0xffffffff)
		logAncillary(g, "IPV6_TCLASS", "tclass", val)
		setAncillaryEnv(g, "IPV6_TCLASS", val)
	}
}

func logAncillary(g *Global, typ, name, val string) {
	if g != nil && g.Log != nil {
		// Classic Info3("ancillary message: %s: %s=%s", ...)
		g.Log.Infof("ancillary message: %s: %s=%s", typ, name, val)
	}
}

func setAncillaryEnv(g *Global, name, val string) {
	// Classic xiosetenv: PROGNAME_NAME (uppercase progname) and SOCAT_NAME.
	prog := "socat"
	if g != nil && g.Progname != "" {
		prog = g.Progname
	}
	up := strings.ToUpper(prog)
	_ = os.Setenv(up+"_"+name, val)
	_ = os.Setenv("SOCAT_"+name, val)
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
func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, network string) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		ApplyAncillaryRecvOpts(int(fd), s)
		ApplyIPSendOpts(int(fd), s, network)
	})
}
