//go:build linux || darwin

package xio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// NeedAncillary reports whether the address requests control messages on recv.
// Recv flags use BoolOption: pktinfo=0 does not enable ReadMsg; presence
// or =1 does.
func NeedAncillary(s parse.Spec) bool {
	return ancillaryRecvRequested(s)
}

// ApplyAncillaryRecvOpts enables kernel delivery of control messages on fd.
// Bare flag → 1; with '=' → integer; =0 disables. Each matching option in
// s.Options is applied in command-line order (ippktinfo then ip-pktinfo=0
// is two setsockopt calls).
func ApplyAncillaryRecvOpts(fd int, s parse.Spec) error {
	family, err := socketIPFamily(fd)
	if err != nil {
		return err
	}
	for _, option := range s.Options {
		e, ok := lookupIPAncillary(specOptionName(option))
		if !ok || e.Kind&IPAncillaryRecv == 0 {
			continue
		}
		if err := applyOneIPRecvOpt(fd, e, option, family); err != nil {
			return err
		}
	}
	return nil
}

func applyOneIPRecvOpt(fd int, e IPAncillaryEntry, option parse.Option, family ipFamily) error {
	n, err := ancillaryRecvOptionInt(option)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Canonical, err)
	}
	if err := rejectIPAncillaryApply(e.Canonical, family); err != nil {
		return err
	}
	level, opt, ok := ancillaryRecvSockopt(e.Canonical)
	if !ok {
		return nil
	}
	if err := setSockoptInt(fd, level, opt, n); err != nil {
		return fmt.Errorf("%s: %w", e.Canonical, err)
	}
	return nil
}

func ancillaryRecvSockopt(canonical string) (level, opt int, ok bool) {
	if level, opt, ok := ancillaryRecvSockoptPlatform(canonical); ok {
		return level, opt, true
	}
	switch canonical {
	case "so-timestamp":
		return unix.SOL_SOCKET, unix.SO_TIMESTAMP, true
	case "ip-pktinfo":
		return unix.IPPROTO_IP, unix.IP_PKTINFO, true
	case "ip-recvttl":
		return unix.IPPROTO_IP, unix.IP_RECVTTL, true
	case "ip-recvtos":
		return unix.IPPROTO_IP, unix.IP_RECVTOS, true
	case "ip-recvopts":
		return unix.IPPROTO_IP, unix.IP_RECVOPTS, true
	case "ip-retopts":
		// Linux IP_RETOPTS is the recv-cmsg flag (same shape as
		// IP_RECVOPTS). Darwin's IP_RETOPTS is an IP-options blob; the
		// matrix hides and rejects the name there.
		return unix.IPPROTO_IP, unix.IP_RETOPTS, true
	case "ipv6-recvpktinfo":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, true
	case "ipv6-recvhoplimit":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, true
	case "ipv6-recvtclass":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, true
	case "ipv6-recvdstopts":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVDSTOPTS, true
	case "ipv6-recvhopopts":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVHOPOPTS, true
	case "ipv6-recvrthdr":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVRTHDR, true
	case "ipv6-recvpathmtu":
		return unix.IPPROTO_IPV6, unix.IPV6_RECVPATHMTU, true
	default:
		return 0, 0, false
	}
}

// ProcessAncillary parses oob from recvmsg, logs Info lines, and sets
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
			// Linux delivers SO_TIMESTAMP; logged as SCM_TIMESTAMP.
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
	// Format: "Mon Jan  2 15:04:05 2006, 000123 usecs"
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
	if handleIPv4CmsgDarwin(typ, data, g) {
		return
	}
	// Do not use a combined switch case for IP_TTL/IP_RECVTTL: the constants
	// can be equal and Go rejects duplicate cases. Linux IP_TTL and Darwin
	// IP_RECVTTL are the same received-TTL cmsg (env IP_TTL).
	if typ == unix.IP_TTL || typ == unix.IP_RECVTTL {
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IP_TTL", "ttl", val)
		SetSessionEnv(g, "IP_TTL", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: ttl=%s", val)
		}
		return
	}
	// Linux and Darwin typically use IP_TOS; also accept IP_RECVTOS.
	if typ == unix.IP_TOS || typ == unix.IP_RECVTOS {
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IP_TOS", "tos", val)
		SetSessionEnv(g, "IP_TOS", val)
		if g != nil && g.Log != nil {
			g.Log.Noticef("Ancillary message: tos=%s", val)
		}
		return
	}
	// Do not combine IP_OPTIONS / IP_RECVOPTS / IP_RETOPTS in one switch
	// case: the constants can collide and Go rejects duplicate cases
	// (same reason as IP_TTL / IP_RECVTTL above).
	// Linux delivers received IP options as IP_RECVOPTS (6) or
	// IP_RETOPTS (7). All three surface as IP_OPTIONS like the recv-opts path.
	if typ == unix.IP_OPTIONS || typ == unix.IP_RECVOPTS || typ == unix.IP_RETOPTS {
		handleIPv4OptionsCmsg(data, g)
		return
	}
	switch typ {
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
	}
}

func handleIPv4OptionsCmsg(data []byte, g *Global) {
	val := hexCmsg(data)
	logAncillary(g, "IP_OPTIONS", "options", val)
	SetSessionEnv(g, "IP_OPTIONS", val)
}

func handleIPv6Cmsg(typ int32, data []byte, g *Global) {
	switch typ {
	case unix.IPV6_PKTINFO:
		ifi, addr, ok := parseInet6Pktinfo(data)
		if !ok {
			return
		}
		dst := ExpandIPv6Full(addr)
		// Full zero-padded form: [0000:0000:...:0001]
		br := "[" + dst + "]"
		ifname := ifIndexName(ifi)
		logAncillary(g, "IPV6_PKTINFO", "dstaddr", br)
		logAncillary(g, "IPV6_PKTINFO", "if", ifname)
		SetSessionEnv(g, "IPV6_DSTADDR", br)
		SetSessionEnv(g, "IPV6_IF", ifname)
	case unix.IPV6_HOPLIMIT:
		val := strconv.Itoa(cmsgInt(data))
		logAncillary(g, "IPV6_HOPLIMIT", "hoplimit", val)
		SetSessionEnv(g, "IPV6_HOPLIMIT", val)
	case unix.IPV6_TCLASS:
		n := cmsgInt(data)
		u, ok := Uint32FromInt(n)
		if !ok {
			return
		}
		// Hex dump of the int value: x000000aa style.
		val := fmt.Sprintf("x%08x", u)
		logAncillary(g, "IPV6_TCLASS", "tclass", val)
		SetSessionEnv(g, "IPV6_TCLASS", val)
	case unix.IPV6_DSTOPTS:
		handleIPv6ExtHdrCmsg("IPV6_DSTOPTS", "dstopts", data, g)
	case unix.IPV6_HOPOPTS:
		handleIPv6ExtHdrCmsg("IPV6_HOPOPTS", "hopopts", data, g)
	case unix.IPV6_RTHDR:
		handleIPv6ExtHdrCmsg("IPV6_RTHDR", "rthdr", data, g)
	case unix.IPV6_PATHMTU:
		handleIPv6GenericCmsg(typ, data, g)
	}
}

func handleIPv6ExtHdrCmsg(typeName, shortName string, data []byte, g *Global) {
	logAncillary(g, typeName, shortName, hexCmsg(data))
}

func handleIPv6GenericCmsg(typ int32, data []byte, g *Global) {
	logAncillary(g, fmt.Sprintf("IPV6.%d", typ), "data", hexCmsg(data))
}

func hexCmsg(data []byte) string {
	return "x" + fmt.Sprintf("%x", data)
}

func logAncillary(g *Global, typ, name, val string) {
	if g != nil && g.Log != nil {
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

// ExpandIPv6Full prints full zero-padded IPv6 (SCM/ENV form).
func ExpandIPv6Full(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// ControlMessageBytes returns the usable control-message bytes from recvmsg.
// MSG_CTRUNC means the kernel truncated ancillary data; do not parse it.
func ControlMessageBytes(oob []byte, oobn, flags int) []byte {
	if flags&unix.MSG_CTRUNC != 0 {
		return nil
	}
	if oobn <= 0 {
		return nil
	}
	if oobn > len(oob) {
		oobn = len(oob)
	}
	return oob[:oobn]
}

// ReadUDPMsg reads one datagram with control messages when needed.
func ReadUDPMsg(c *net.UDPConn, p []byte, wantCtrl bool) (n int, oob []byte, addr *net.UDPAddr, err error) {
	if !wantCtrl {
		n, addr, err = c.ReadFromUDP(p)
		return n, nil, addr, err
	}
	oob = make([]byte, 1024)
	var oobn, flags int
	n, oobn, flags, addr, err = c.ReadMsgUDP(p, oob)
	if err != nil {
		return n, nil, nil, err
	}
	return n, ControlMessageBytes(oob, oobn, flags), addr, nil
}

// ApplyUDPConnOpts applies late buffers and remaining SOL_SOCKET options
// on a live UDPConn. Send and recv IP/ancillary options apply after
// socket() (DialControl / ListenControl → ApplyPastSocketPhase) and must
// not be re-applied here after bind/connect.
func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, _ string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		// so-sndbuf-late / so-rcvbuf-late on the raw UDP fd after
		// bind/connect, before packet-session wrapping (udpRecvFromConn).
		// ApplySocketOptions / setsockopt-socket / broadcast apply in
		// listen/dial Control before bind/connect.
		if optionErr == nil {
			optionErr = ApplyLateSocketOptions(int(fd), s)
		}
		if optionErr == nil {
			optionErr = ApplyGenericSetsockopt(int(fd), s, SockoptPhaseConnected)
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	// append/perm/user/group/ftruncate on the raw UDP socket before
	// packet-session wrapping (udpFilteredRecv / udpRecvFromConn).
	return ApplyFDLifecycleToConn(c, s)
}
