package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
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
	{Canonical: "so-timestamp", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-pktinfo", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvttl", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvtos", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-recvopts", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-retopts", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ip-recvdstaddr", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{Canonical: "ip-recvif", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{Canonical: "ipv6-recvpktinfo", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvhoplimit", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvtclass", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvdstopts", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ipv6-recvhopopts", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{Canonical: "ipv6-recvrthdr", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-recvpathmtu", Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},

	{Canonical: "ip-ttl", Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{Canonical: "ip-tos", Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{Canonical: "ip-options", Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ip-hdrincl", Kind: IPAncillarySend, Groups: []string{GroupRawIP}, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-unicast-hops", Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{Canonical: "ipv6-tclass", Kind: IPAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
}

func lookupIPAncillary(optionName string) (IPAncillaryEntry, bool) {
	n := strings.ToLower(strings.TrimSpace(optionName))
	if n == "" {
		return IPAncillaryEntry{}, false
	}
	d, ok := optionmeta.Lookup(n)
	if !ok {
		return IPAncillaryEntry{}, false
	}
	for _, e := range ipAncillaryMatrix {
		if e.Canonical == d.Canonical {
			return e, true
		}
	}
	return IPAncillaryEntry{}, false
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
	return e.platforms == 0 || e.platforms&ipAncillaryThisPlatform != 0
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

func preparedForcedIPFamily(config addrconfig.Address) ipFamily {
	if v, ok := VersionFromPF(ProtocolFamilyText(config)); ok {
		switch v {
		case IPv4:
			return ipFamilyV4
		case IPv6:
			return ipFamilyV6
		}
	}
	return ipFamilyFromAddressType(config.Type)
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
func RejectUnsupportedIPAncillary(s addrconfig.Address) error {
	reg, ok := AddressRegistrationForType(s.Type)
	if !ok {
		return nil
	}
	config := s
	family := preparedForcedIPFamily(config)
	if family == ipFamilyUnknown {
		family = ipFamilyFromAddressType(s.Type)
	}
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		name, _, ok := ancillaryOptionIdentity(action.Ancillary)
		if !ok {
			continue
		}
		e, inMatrix := lookupIPAncillary(name)
		if !inMatrix {
			continue
		}
		if !e.supportedOnThisPlatform() {
			return fmt.Errorf("%s: option %q not supported on this platform", s.Type, name)
		}
		if !IPAncillarySupported(reg.Group, name) {
			return fmt.Errorf("%s: option %q not supported with this address type", s.Type, name)
		}
		if family != ipFamilyUnknown && !e.supportedOnFamily(family) {
			return fmt.Errorf("%s: option %q not supported on %s", s.Type, name, ipFamilyName(family))
		}
	}
	return nil
}

func ipSendRequested(s addrconfig.Address) bool {
	config := s
	return preparedIPSendRequested(config)
}

func preparedIPSendRequested(config addrconfig.Address) bool {
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		if _, kind, ok := ancillaryOptionIdentity(action.Ancillary); ok && kind&IPAncillarySend != 0 {
			return true
		}
	}
	return false
}

func ancillaryRecvRequested(s addrconfig.Address) bool {
	config := s
	return preparedAncillaryRecvRequested(config)
}

func preparedAncillaryRecvRequested(config addrconfig.Address) bool {
	last := make(map[addrconfig.AncillaryOption]int)
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		if _, kind, ok := ancillaryOptionIdentity(action.Ancillary); !ok || kind&IPAncillaryRecv == 0 {
			continue
		}
		last[action.Ancillary] = action.Number
	}
	for _, n := range last {
		if n != 0 {
			return true
		}
	}
	return false
}

func ancillaryOptionIdentity(opt addrconfig.AncillaryOption) (canonical string, kind IPAncillaryKind, ok bool) {
	switch opt {
	case addrconfig.AncillaryTimestamp:
		return "so-timestamp", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4PacketInfo:
		return "ip-pktinfo", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RecvTTL:
		return "ip-recvttl", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RecvTOS:
		return "ip-recvtos", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RecvOptions:
		return "ip-recvopts", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RetOptions:
		return "ip-retopts", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RecvDstAddr:
		return "ip-recvdstaddr", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4RecvInterface:
		return "ip-recvif", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6PacketInfo:
		return "ipv6-recvpktinfo", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvHopLimit:
		return "ipv6-recvhoplimit", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvTrafficClass:
		return "ipv6-recvtclass", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvDstOptions:
		return "ipv6-recvdstopts", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvHopOptions:
		return "ipv6-recvhopopts", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvRoutingHeader:
		return "ipv6-recvrthdr", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv6RecvPathMTU:
		return "ipv6-recvpathmtu", IPAncillaryRecv, true
	case addrconfig.AncillaryIPv4TTL:
		return "ip-ttl", IPAncillarySend, true
	case addrconfig.AncillaryIPv4TOS:
		return "ip-tos", IPAncillarySend, true
	case addrconfig.AncillaryIPv4Options:
		return "ip-options", IPAncillarySend, true
	case addrconfig.AncillaryIPv4HeaderIncluded:
		return "ip-hdrincl", IPAncillarySend, true
	case addrconfig.AncillaryIPv6UnicastHops:
		return "ipv6-unicast-hops", IPAncillarySend, true
	case addrconfig.AncillaryIPv6TrafficClass:
		return "ipv6-tclass", IPAncillarySend, true
	default:
		return "", 0, false
	}
}
