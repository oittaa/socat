//go:build linux

package addr

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// openTUN creates a Linux TUN/TAP device (classic TUN:addr/bits).
// Syntax: TUN[:<ipv4>/<bits>][,tun-name=…][,tun-type=tun|tap][,iff-up][,if-mtu=N]…
func openTUN(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Classic allows 0 or 1 positional (CIDR). testaddrs probes TUN::::: must fail fast.
	addrSpec, err := tunPositional(s)
	if err != nil {
		return nil, err
	}
	dev := s.OptionValue("tun-device", "/dev/net/tun")
	if dev == "" {
		dev = "/dev/net/tun"
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open(%q): %w", dev, err)
	}
	fd := int(f.Fd())

	// Flags: IFF_TUN (default) or IFF_TAP; optional IFF_NO_PI.
	flags := uint16(unix.IFF_TUN)
	tunType := strings.ToLower(s.OptionValue("tun-type", "tun"))
	if tunType == "" {
		tunType = "tun"
	}
	switch tunType {
	case "tun":
		flags = unix.IFF_TUN
	case "tap":
		flags = unix.IFF_TAP
	default:
		f.Close()
		return nil, fmt.Errorf("unknown tun-type %q", tunType)
	}
	if s.HasOption("iff-no-pi") || s.HasOption("no-pi") {
		if s.BoolOption("iff-no-pi") || s.BoolOption("no-pi") {
			flags |= unix.IFF_NO_PI
		}
	}

	name := s.OptionValue("tun-name", "")
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("tun-name: %w", err)
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		f.Close()
		return nil, fmt.Errorf("ioctl(TUNSETIFF, %q): %w", name, err)
	}
	ifname := ifr.Name()
	if g != nil && g.Log != nil {
		g.Log.Noticef("TUN: new device %q", ifname)
	}

	// Control socket for address / flags / mtu.
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("socket(AF_INET): %w", err)
	}
	defer unix.Close(sock)

	// Disable IPv6 on this iface before UP so kernel NDP/MLD does not inject
	// extra frames into INTERFACE / TUN streams (TUNINTERFACE expects clean echo).
	disableIPv6OnIface(ifname)

	// Optional TUN:addr/bits
	if addrSpec != "" {
		if err := setTunIPv4(sock, ifname, addrSpec); err != nil {
			f.Close()
			return nil, err
		}
	}

	// Interface flags (iff-up, …) and MTU.
	if err := applyInterfaceOpts(sock, ifname, s); err != nil {
		f.Close()
		return nil, err
	}

	_ = mode
	// Wrap TUN fd: drop IPv6 link-local multicast (MLD/ND) so TUN…PIPE does
	// not re-inject them into INTERFACE (classic TUNINTERFACE).
	noPI := flags&unix.IFF_NO_PI != 0
	st := relay.Stream(&tunStream{f: f, noPI: noPI})
	st, err = wrapCommon(s, st)
	if err != nil {
		f.Close()
		return nil, err
	}
	o := &Opened{
		Stream: st,
		Label:  "TUN:" + ifname,
	}
	o.addCleanup(func() { f.Close() })
	return o, nil
}

// tunStream is a TUN/TAP char-device stream. Read skips IPv6 multicast noise
// from the kernel (MLD/ND) that would otherwise be echoed via PIPE into
// INTERFACE. Unicast IPv4/IPv6 and non-multicast frames pass through.
type tunStream struct {
	f    *os.File
	noPI bool
}

func (t *tunStream) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(p)
		if err != nil || n == 0 {
			return n, err
		}
		if isTunIPv6Multicast(p[:n], t.noPI) {
			continue
		}
		return n, nil
	}
}

func (t *tunStream) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *tunStream) Close() error                 { return t.f.Close() }
func (t *tunStream) ShutdownWrite() error {
	// Do not close the TUN fd on half-close — the peer direction still needs it
	// (same as PTY master). Full Close runs when the transfer ends.
	return nil
}

// isTunIPv6Multicast reports kernel IPv6 MLD/ND-style multicast on TUN.
func isTunIPv6Multicast(b []byte, noPI bool) bool {
	off := 0
	if !noPI {
		if len(b) < 4 {
			return false
		}
		proto := binary.BigEndian.Uint16(b[2:4])
		if proto != unix.ETH_P_IPV6 {
			return false
		}
		off = 4
	} else {
		if len(b) < 1 || b[0]>>4 != 6 {
			return false
		}
	}
	// IPv6 destination address starts at offset 24 within the IP header.
	if len(b) < off+24+1 {
		return false
	}
	return b[off+24] == 0xff
}

// setTunIPv4 configures IPv4 address and netmask from "a.b.c.d/bits" or "a.b.c.d".
func setTunIPv4(sock int, ifname, spec string) error {
	spec = strings.TrimSpace(spec)
	var ip net.IP
	var mask net.IPMask
	if strings.Contains(spec, "/") {
		ipp, ipnet, err := net.ParseCIDR(spec)
		if err != nil {
			return fmt.Errorf("TUN address %q: %w", spec, err)
		}
		ip = ipp.To4()
		if ip == nil {
			return fmt.Errorf("TUN address %q: IPv4 required", spec)
		}
		mask = ipnet.Mask
	} else {
		ip = net.ParseIP(spec)
		if ip == nil {
			return fmt.Errorf("TUN address %q: invalid", spec)
		}
		ip = ip.To4()
		if ip == nil {
			return fmt.Errorf("TUN address %q: IPv4 required", spec)
		}
		mask = net.CIDRMask(24, 32) // classic default when only ifaddr given
	}

	ifr, err := unix.NewIfreq(ifname)
	if err != nil {
		return err
	}
	if err := ifr.SetInet4Addr([]byte(ip)); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFADDR, %s=%s): %w", ifname, ip, err)
	}
	if err := ifr.SetInet4Addr([]byte(mask)); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFNETMASK, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFNETMASK, %s): %w", ifname, err)
	}
	return nil
}

// applyInterfaceOpts applies iff-* flags and if-mtu / interface-mtu.
func applyInterfaceOpts(sock int, ifname string, s parse.Spec) error {
	ifr, err := unix.NewIfreq(ifname)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCGIFFLAGS, %s): %w", ifname, err)
	}
	flags := ifr.Uint16()
	set, clear := parseIffOpts(s)
	flags |= set
	flags &^= clear
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFFLAGS, %s): %w", ifname, err)
	}

	mtuStr := firstNonEmpty(s.OptionValue("if-mtu", ""), s.OptionValue("interface-mtu", ""))
	if mtuStr != "" {
		mtu, err := strconv.ParseUint(mtuStr, 10, 32)
		if err != nil || mtu == 0 {
			return fmt.Errorf("if-mtu: invalid %q", mtuStr)
		}
		ifr2, err := unix.NewIfreq(ifname)
		if err != nil {
			return err
		}
		ifr2.SetUint32(uint32(mtu))
		if err := unix.IoctlIfreq(sock, unix.SIOCSIFMTU, ifr2); err != nil {
			return fmt.Errorf("ioctl(SIOCSIFMTU, %s=%d): %w", ifname, mtu, err)
		}
	}
	return nil
}

// parseIffOpts maps classic iff-up / iff-noarp / … to set and clear masks.
// Bare flag or =1 sets the bit; =0 clears it.
func parseIffOpts(s parse.Spec) (set, clear uint16) {
	type iffOpt struct {
		names []string
		bit   uint16
	}
	opts := []iffOpt{
		{[]string{"iff-up", "up"}, unix.IFF_UP},
		{[]string{"iff-broadcast"}, unix.IFF_BROADCAST},
		{[]string{"iff-debug"}, unix.IFF_DEBUG},
		{[]string{"iff-loopback", "loopback"}, unix.IFF_LOOPBACK},
		{[]string{"iff-pointopoint", "pointopoint"}, unix.IFF_POINTOPOINT},
		{[]string{"iff-running", "running"}, unix.IFF_RUNNING},
		{[]string{"iff-noarp", "noarp"}, unix.IFF_NOARP},
		{[]string{"iff-promisc", "promisc"}, unix.IFF_PROMISC},
		{[]string{"iff-allmulti", "allmulti"}, unix.IFF_ALLMULTI},
		{[]string{"iff-multicast"}, unix.IFF_MULTICAST},
	}
	for _, o := range opts {
		for _, n := range o.names {
			if !s.HasOption(n) {
				continue
			}
			if s.BoolOption(n) {
				set |= o.bit
			} else {
				clear |= o.bit
			}
			break
		}
	}
	return set, clear
}

// tunPositional returns the optional CIDR argument, or error on bad arity.
func tunPositional(s parse.Spec) (string, error) {
	// Drop trailing empties from "TUN:" ; reject extra fields like "TUN:::::".
	n := 0
	for _, p := range s.Params {
		if p != "" {
			n++
		}
	}
	if n > 1 {
		return "", fmt.Errorf("too many parameters (%d instead of 0 or 1)", len(s.Params))
	}
	if len(s.Params) > 1 {
		// e.g. TUN::::: → five empty params from testaddrs probes
		return "", fmt.Errorf("too many parameters (%d instead of 0 or 1)", len(s.Params))
	}
	if len(s.Params) == 1 {
		return s.Params[0], nil
	}
	return "", nil
}

// openINTERFACE opens a Linux AF_PACKET SOCK_RAW socket on a named interface.
// Syntax: INTERFACE:<ifname>
func openINTERFACE(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Exactly one non-empty name; INTERFACE::::: must fail (testaddrs).
	if len(s.Params) != 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("INTERFACE requires interface name")
	}
	// Extra empty fields from INTERFACE:foo:::: — still wrong arity for classic.
	// (Parse of INTERFACE::::: is params=["","","","",""] → caught above.)
	ifname := s.Params[0]

	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("unknown interface %q: %w", ifname, err)
	}

	proto := htons(uint16(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w", err)
	}

	// Apply interface flags / MTU if requested (shared with TUN).
	csock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err == nil {
		_ = applyInterfaceOpts(csock, ifname, s)
		unix.Close(csock)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind(AF_PACKET, %s): %w", ifname, err)
	}

	// Classic: ignore locally originated packets (INTERFACE_IGNOREOUTGOING).
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
		// Non-fatal: older kernels; filter in userspace below.
		if g != nil && g.Log != nil {
			g.Log.Warningf("setsockopt(PACKET_IGNORE_OUTGOING): %s", err)
		}
	}

	f := os.NewFile(uintptr(fd), "interface:"+ifname)
	st := relay.Stream(&packetRawStream{
		f:       f,
		fd:      fd,
		ifindex: ifi.Index,
		proto:   proto,
	})
	st, err = wrapCommon(s, st)
	if err != nil {
		f.Close()
		return nil, err
	}
	_ = mode
	o := &Opened{Stream: st, Label: "INTERFACE:" + ifname}
	o.addCleanup(func() { f.Close() })
	return o, nil
}

// disableIPv6OnIface turns off IPv6 autoconfig for ifname (best-effort).
// Docker often mounts /proc/sys read-only — failure is ignored.
func disableIPv6OnIface(ifname string) {
	path := "/proc/sys/net/ipv6/conf/" + ifname + "/disable_ipv6"
	_ = os.WriteFile(path, []byte("1\n"), 0o644)
}

// packetRawStream is AF_PACKET SOCK_RAW read/write for INTERFACE.
// Read drops PACKET_OUTGOING when the kernel option is unavailable.
type packetRawStream struct {
	f       *os.File
	fd      int
	ifindex int
	proto   uint16
	closed  bool
}

func (p *packetRawStream) Read(b []byte) (int, error) {
	for {
		n, from, err := unix.Recvfrom(p.fd, b, 0)
		if err != nil {
			return 0, err
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok {
			// PACKET_OUTGOING = 4 — skip our own transmit copies.
			if ll.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
		}
		return n, nil
	}
}

func (p *packetRawStream) Write(b []byte) (int, error) {
	sa := &unix.SockaddrLinklayer{
		Protocol: p.proto,
		Ifindex:  p.ifindex,
	}
	if err := unix.Sendto(p.fd, b, 0, sa); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetRawStream) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return p.f.Close()
}

func (p *packetRawStream) ShutdownWrite() error {
	// Prefer SHUT_WR so a still-running Read can finish the echo (TUNINTERFACE).
	// Fall back to no-op; full Close is applied when the transfer cancels.
	if err := unix.Shutdown(p.fd, unix.SHUT_WR); err != nil {
		return nil
	}
	return nil
}

// Fd exposes the packet socket for relay backpressure/poll.
func (p *packetRawStream) Fd() uintptr { return uintptr(p.fd) }

// htons converts a uint16 to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
