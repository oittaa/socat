package xio

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// IPAncillaryKind is a bitmask of runtime effects implemented for one
// IP/ancillary option. Combinations that are not listed are rejected
// instead of being accepted as no-ops.
type IPAncillaryKind uint8

const (
	// IPAncillaryRecv requires a ReadMsg/ReadMsgUDP/ReadMsgIP path that
	// surfaces cmsg data (SOCAT_* / session env).
	IPAncillaryRecv IPAncillaryKind = 1 << iota
	// IPAncillarySend applies a send-side setsockopt (TTL, TOS, hop limit, …).
	IPAncillarySend
)

type ipAncillaryFamily uint8

const (
	ipAncillaryFamilyV4 ipAncillaryFamily = 1 << iota
	ipAncillaryFamilyV6
	ipAncillaryFamilyAny = ipAncillaryFamilyV4 | ipAncillaryFamilyV6
)

type ipAncillaryPlatform uint8

const (
	ipAncillaryUnix ipAncillaryPlatform = 1 << iota
	ipAncillaryWindows
	ipAncillaryDarwin
	ipAncillaryLinux
)

type ipFamily uint8

const (
	ipFamilyUnknown ipFamily = iota
	ipFamilyV4
	ipFamilyV6
)

// IPAncillaryEntry is one row of the address-family × option runtime matrix.
// Only the groups, platforms, and IP families listed here are honored.
type IPAncillaryEntry struct {
	Canonical string
	Aliases   []string
	Kind      IPAncillaryKind
	Groups    []string
	families  ipAncillaryFamily
	platforms ipAncillaryPlatform
}

// ipAncillaryRecvGroups are datagram address families whose I/O path uses
// ReadMsg when a recv ancillary option is set.
var ipAncillaryRecvGroups = []string{GroupUDP, GroupRawIP}

// ipAncillarySendGroups are families that apply send-side IP socket options
// on the underlying INET fd once after socket() (DialControl /
// ListenControl → ApplyNetworkSocketOptions / ApplyPastSocketPhase).
var ipAncillarySendGroups = []string{
	GroupUDP, GroupRawIP, GroupTCP, GroupSCTP,
	GroupTLS, GroupDTLS, GroupWebSocket, GroupProxy, GroupQUIC,
}

var (
	ipAncillaryUnixOnly    = ipAncillaryUnix
	ipAncillaryUnixWindows = ipAncillaryUnix | ipAncillaryWindows
	ipAncillaryDarwinOnly  = ipAncillaryDarwin
	ipAncillaryLinuxOnly   = ipAncillaryLinux
	ipAncillaryIPv4        = ipAncillaryFamilyV4
	ipAncillaryIPv6        = ipAncillaryFamilyV6
	ipAncillaryIPv4AndIPv6 = ipAncillaryFamilyAny
)

// ipAncillaryMatrix is the authoritative runtime support table. CLI
// implementationGroups are derived from it; OpenSpec rejects the same
// combinations. Recv ancillary is not advertised on TCP or QUIC: stream TCP
// and quic-go's PacketConn do not surface cmsgs. Send-side options are
// advertised on QUIC because they are applied to the transport UDP fd.
//
// Recv ancillary is Unix-only: Windows NeedAncillary cannot enable ReadMsg
// cmsg delivery. Empty implementationGroups means unrestricted, so Windows
// recv rows keep UDP/raw-IP groups and are rejected by platform instead.
//
// ip-ttl/ip-tos/ip-options use IPPROTO_IP IP_TTL/IP_TOS/IP_OPTIONS on both
// IPv4 and IPv6 sockets — not IPV6_UNICAST_HOPS translation and not a silent
// skip of TOS on v6. ipv6-unicast-hops/ipv6-tclass and ipv6 recv opts are
// IPv6-only.
//
// IP_HDRINCL is only meaningful on SOCK_RAW IPv4, so ip-hdrincl is advertised
// and applied only there and rejected on TCP, UDP, QUIC, IPv6, Windows, and
// other non-raw address types.
//
// ip-retopts is Linux-only recv ancillary (IP_RETOPTS as an int flag like
// IP_RECVOPTS). Darwin IP_RETOPTS is an IP-options blob, so the name is
// hidden and rejected there. ip-recvdstaddr / ip-recvif are Darwin-only.
// ip-recverr is applied as SOL_IP/IP_RECVERR on Linux IPv4 and IPv6 sockets
// (see recverr_linux.go). ipv6-recverr stays rejected. ip-mtu and ip-pktoptions
// are recognized get-only names, not this matrix. ip-router-alert is a
// Linux raw-IPv4 setter outside this matrix (see ip_remaining.go).
//
// ipv6-recvdstopts / ipv6-recvhopopts are Linux-only int recv flags:
// Darwin accepts setsockopt but getsockopt stays 0. ipv6-recvrthdr /
// ipv6-recvpathmtu round-trip on Linux and Darwin. Windows has no
// ReadMsg cmsg path. There is no recvpathmtu parser alias.

var ipAncillaryMatrix = []IPAncillaryEntry{
	{Canonical: "so-timestamp", Aliases: []string{"timestamp"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-pktinfo", Aliases: []string{"pktinfo", "ippktinfo"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvttl", Aliases: []string{"recvttl", "iprecvttl"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvtos", Aliases: []string{"recvtos", "iprecvtos"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvopts", Aliases: []string{"recvopts", "iprecvopts"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-retopts", Aliases: []string{"retopts", "ipretopts"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ip-recvdstaddr", Aliases: []string{"recvdstaddr", "iprecvdstaddr"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{Canonical: "ip-recvif", Aliases: []string{"recvif"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{Canonical: "ipv6-recvpktinfo", Aliases: []string{"recvpktinfo"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvhoplimit", Aliases: []string{"recvhoplimit"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvtclass", Aliases: []string{"recvtclass"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvdstopts", Aliases: []string{"recvdstopts"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ipv6-recvhopopts", Aliases: []string{"recvhopopts"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ipv6-recvrthdr", Aliases: []string{"recvrthdr"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvpathmtu", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},

	{Canonical: "ip-ttl", Aliases: []string{"ttl", "ipttl"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{Canonical: "ip-tos", Aliases: []string{"tos", "iptos"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{Canonical: "ip-options", Aliases: []string{"ipoptions"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-hdrincl", Aliases: []string{"hdrincl", "iphdrincl"}, Kind: IPAncillarySend, Groups: []string{GroupRawIP}, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-unicast-hops", Aliases: []string{"unicast-hops"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-tclass", Aliases: []string{"tclass"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
}

func lookupIPAncillary(optionName string) (IPAncillaryEntry, bool) {
	n := strings.ToLower(strings.TrimSpace(optionName))
	if n == "" {
		return IPAncillaryEntry{}, false
	}
	canon := parse.CanonicalOptionName(n)
	for _, e := range ipAncillaryMatrix {
		if e.Canonical == n || e.Canonical == canon {
			return e, true
		}
		for _, alias := range e.Aliases {
			if alias == n || alias == canon {
				return e, true
			}
		}
	}
	return IPAncillaryEntry{}, false
}

// IPAncillaryNames returns every canonical name and alias in the matrix.
func IPAncillaryNames() []string {
	var out []string
	for _, e := range ipAncillaryMatrix {
		out = append(out, e.Canonical)
		out = append(out, e.Aliases...)
	}
	return out
}

// IPAncillaryImplementationGroups is the CLI implementationGroups list for
// one option. Unknown names return nil (no extra restriction). Matrix rows
// always return their address groups, including Unix-only recv options on
// Windows: a nil/empty list would mean unrestricted.
func IPAncillaryImplementationGroups(optionName string) []string {
	e, ok := lookupIPAncillary(optionName)
	if !ok {
		return nil
	}
	return append([]string(nil), e.Groups...)
}

// IPAncillarySupported reports whether optionName is implemented on the
// address help-section group. Options that are not in the matrix are
// unrestricted here. Platform and IP-family checks live in
// RejectUnsupportedIPAncillary.
func IPAncillarySupported(group, optionName string) bool {
	e, ok := lookupIPAncillary(optionName)
	if !ok {
		return true
	}
	for _, candidate := range e.Groups {
		if group == candidate {
			return true
		}
	}
	return false
}

func (e IPAncillaryEntry) supportedOnThisPlatform() bool {
	if e.platforms == 0 {
		return true
	}
	if runtime.GOOS == "windows" {
		return e.platforms&ipAncillaryWindows != 0
	}
	if e.platforms&ipAncillaryLinux != 0 && runtime.GOOS == "linux" {
		return true
	}
	if runtime.GOOS == "darwin" {
		if e.platforms&ipAncillaryDarwin != 0 {
			return true
		}
		return e.platforms&ipAncillaryUnix != 0
	}
	return e.platforms&ipAncillaryUnix != 0
}

func (e IPAncillaryEntry) supportedOnFamily(family ipFamily) bool {
	if e.families == 0 || e.families == ipAncillaryFamilyAny {
		return true
	}
	switch family {
	case ipFamilyV4:
		return e.families&ipAncillaryFamilyV4 != 0
	case ipFamilyV6:
		return e.families&ipAncillaryFamilyV6 != 0
	default:
		return false
	}
}

func ipFamilyName(family ipFamily) string {
	switch family {
	case ipFamilyV4:
		return "IPv4"
	case ipFamilyV6:
		return "IPv6"
	default:
		return "this address family"
	}
}

func specForcedIPFamily(s parse.Spec) ipFamily {
	if pf := s.OptionValue("pf", ""); pf != "" {
		if v, ok := VersionFromPF(pf); ok {
			switch v {
			case IPv4:
				return ipFamilyV4
			case IPv6:
				return ipFamilyV6
			}
		}
	}
	return ipFamilyFromAddressType(s.Type)
}

func ipFamilyFromAddressType(typ string) ipFamily {
	u := strings.ToUpper(strings.TrimSpace(typ))
	for _, prefix := range []string{"TCP", "UDP", "SCTP", "IP"} {
		if !strings.HasPrefix(u, prefix) {
			continue
		}
		rest := u[len(prefix):]
		switch {
		case strings.HasPrefix(rest, "4"):
			return ipFamilyV4
		case strings.HasPrefix(rest, "6"):
			return ipFamilyV6
		}
	}
	return ipFamilyUnknown
}

func ipFamilyFromNetwork(network string) ipFamily {
	n := strings.ToLower(network)
	if i := strings.IndexByte(n, ':'); i >= 0 {
		n = n[:i]
	}
	switch {
	case strings.HasSuffix(n, "4"):
		return ipFamilyV4
	case strings.HasSuffix(n, "6"):
		return ipFamilyV6
	default:
		return ipFamilyUnknown
	}
}

func rejectIPAncillaryApply(optionName string, family ipFamily) error {
	e, ok := lookupIPAncillary(optionName)
	if !ok {
		return nil
	}
	if !e.supportedOnThisPlatform() {
		return fmt.Errorf("%s: not supported on this platform", optionName)
	}
	if family != ipFamilyUnknown && !e.supportedOnFamily(family) {
		return fmt.Errorf("%s: not supported on %s", optionName, ipFamilyName(family))
	}
	return nil
}

// RejectUnsupportedIPAncillary fails fast when a spec requests an IP/ancillary
// option the opener group, platform, or forced IP family does not implement.
// Same combinations the CLI rejects via implementationGroups, plus Windows
// recv/ip-options/ipv6-* and IPv4/IPv6 mismatches.
func RejectUnsupportedIPAncillary(s parse.Spec) error {
	reg, ok := AddressRegistrationForType(s.Type)
	if !ok {
		return nil
	}
	family := specForcedIPFamily(s)
	for _, option := range s.Options {
		name := specOptionName(option)
		e, inMatrix := lookupIPAncillary(name)
		if !inMatrix {
			continue
		}
		if !e.supportedOnThisPlatform() {
			return fmt.Errorf("%s: option %q not supported on this platform", s.Type, option.Name)
		}
		if !IPAncillarySupported(reg.Group, name) {
			return fmt.Errorf("%s: option %q not supported with this address type", s.Type, option.Name)
		}
		if family != ipFamilyUnknown && !e.supportedOnFamily(family) {
			return fmt.Errorf("%s: option %q not supported on %s", s.Type, option.Name, ipFamilyName(family))
		}
	}
	return nil
}

func (e IPAncillaryEntry) names() []string {
	out := make([]string, 0, 1+len(e.Aliases))
	out = append(out, e.Canonical)
	out = append(out, e.Aliases...)
	return out
}

func ipSendRequested(s parse.Spec) bool {
	for _, e := range ipAncillaryMatrix {
		if e.Kind&IPAncillarySend == 0 {
			continue
		}
		for _, name := range e.names() {
			if s.HasOption(name) {
				return true
			}
		}
	}
	return false
}

func ancillaryRecvRequested(s parse.Spec) bool {
	for _, e := range ipAncillaryMatrix {
		if e.Kind&IPAncillaryRecv == 0 {
			continue
		}
		for _, name := range e.names() {
			if s.BoolOption(name) {
				return true
			}
		}
	}
	return false
}

func ancillaryRecvOptionInt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	switch v {
	case "", "0", "false", "no", "off":
		return 0, nil
	case "1", "true", "yes", "on":
		return 1, nil
	}
	n, err := ParseIntAny(o.Value)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ancillaryRecvInt returns the final int value after canonical alias
// folding. NeedAncillary uses the same last-wins view to decide whether the
// I/O path must call recvmsg; the apply path still walks every occurrence
// in command-line order.
func ancillaryRecvInt(s parse.Spec, names ...string) (int, bool, error) {
	for _, name := range names {
		o, ok := s.OptionNamed(name)
		if !ok {
			continue
		}
		n, err := ancillaryRecvOptionInt(o)
		if err != nil {
			return 0, true, fmt.Errorf("%s: %w", name, err)
		}
		return n, true, nil
	}
	return 0, false, nil
}
