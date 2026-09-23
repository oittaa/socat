package sockopt

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
)

// AddressGroup resolves an address type to its help-section group.
// The xio registry registers the implementation.
var AddressGroup func(typ string) (group string, ok bool)

// ipAncillaryKind is a bitmask of runtime effects implemented for one
// IP/ancillary option. Combinations that are not listed are rejected
// instead of being accepted as no-ops.
type ipAncillaryKind uint8

const (
	// ipAncillaryRecv requires a ReadMsg/ReadMsgUDP/ReadMsgIP path that
	// surfaces cmsg data (SOCAT_* / session env).
	ipAncillaryRecv ipAncillaryKind = 1 << iota
	// ipAncillarySend applies a send-side setsockopt (TTL, TOS, hop limit, …).
	ipAncillarySend
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

type IPFamily uint8

const (
	ipFamilyUnknown IPFamily = iota
	ipFamilyV4
	IPFamilyV6
)

// ipAncillaryEntry is one row of the address-family × option runtime matrix.
// Only the groups, platforms, and IP families listed here are honored.
type ipAncillaryEntry struct {
	ID        addrconfig.AncillaryOption
	Canonical string
	Kind      ipAncillaryKind
	Groups    []string
	families  ipAncillaryFamily
	platforms ipAncillaryPlatform
}

// ipAncillaryRecvGroups are datagram address families whose I/O path uses
// ReadMsg when a recv ancillary option is set.
var ipAncillaryRecvGroups = []string{optionmeta.GroupUDP, optionmeta.GroupRawIP}

// ipAncillarySendGroups are families that apply send-side IP socket options
// on the underlying INET fd once after socket() (DialControl /
// ListenControl → ApplyNetworkSocketOptions / ApplyPastSocketPhase).
var ipAncillarySendGroups = []string{
	optionmeta.GroupUDP, optionmeta.GroupRawIP, optionmeta.GroupTCP, optionmeta.GroupSCTP,
	optionmeta.GroupTLS, optionmeta.GroupDTLS, optionmeta.GroupWebSocket, optionmeta.GroupProxy, optionmeta.GroupQUIC,
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
// implementationGroups are derived from it; PrepareSpec rejects the same
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

var ipAncillaryMatrix = []ipAncillaryEntry{
	{ID: addrconfig.AncillarySOTimestamp, Canonical: "so-timestamp", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPPktinfo, Canonical: "ip-pktinfo", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPRecvTTL, Canonical: "ip-recvttl", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPRecvTOS, Canonical: "ip-recvtos", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPRecvOpts, Canonical: "ip-recvopts", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPRetOpts, Canonical: "ip-retopts", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryLinuxOnly},
	{ID: addrconfig.AncillaryIPRecvDstAddr, Canonical: "ip-recvdstaddr", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{ID: addrconfig.AncillaryIPRecvIf, Canonical: "ip-recvif", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv4, platforms: ipAncillaryDarwinOnly},
	{ID: addrconfig.AncillaryIPv6RecvPktinfo, Canonical: "ipv6-recvpktinfo", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6RecvHopLimit, Canonical: "ipv6-recvhoplimit", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6RecvTclass, Canonical: "ipv6-recvtclass", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6RecvDstOpts, Canonical: "ipv6-recvdstopts", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{ID: addrconfig.AncillaryIPv6RecvHopOpts, Canonical: "ipv6-recvhopopts", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryLinuxOnly},
	{ID: addrconfig.AncillaryIPv6RecvRtHdr, Canonical: "ipv6-recvrthdr", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6RecvPathMTU, Canonical: "ipv6-recvpathmtu", Kind: ipAncillaryRecv, Groups: ipAncillaryRecvGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},

	{ID: addrconfig.AncillaryIPTTL, Canonical: "ip-ttl", Kind: ipAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{ID: addrconfig.AncillaryIPTOS, Canonical: "ip-tos", Kind: ipAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixWindows},
	{ID: addrconfig.AncillaryIPOptions, Canonical: "ip-options", Kind: ipAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv4AndIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPHdrincl, Canonical: "ip-hdrincl", Kind: ipAncillarySend, Groups: []string{optionmeta.GroupRawIP}, families: ipAncillaryIPv4, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6UnicastHops, Canonical: "ipv6-unicast-hops", Kind: ipAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
	{ID: addrconfig.AncillaryIPv6Tclass, Canonical: "ipv6-tclass", Kind: ipAncillarySend, Groups: ipAncillarySendGroups, families: ipAncillaryIPv6, platforms: ipAncillaryUnixOnly},
}

func lookupIPAncillary(id addrconfig.AncillaryOption) (ipAncillaryEntry, bool) {
	if id == addrconfig.AncillaryNone {
		return ipAncillaryEntry{}, false
	}
	for _, e := range ipAncillaryMatrix {
		if e.ID == id {
			return e, true
		}
	}
	return ipAncillaryEntry{}, false
}

// ipAncillarySupported reports whether option is implemented on the
// address help-section group. Options that are not in the matrix are
// unrestricted here. Platform and IP-family checks live in
// rejectUnsupportedIPAncillary.
func IPAncillarySupported(group string, option addrconfig.AncillaryOption) bool {
	e, ok := lookupIPAncillary(option)
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

func (e ipAncillaryEntry) supportedOnThisPlatform() bool {
	return e.platforms == 0 || e.platforms&ipAncillaryThisPlatform != 0
}

func (e ipAncillaryEntry) supportedOnFamily(family IPFamily) bool {
	if e.families == 0 || e.families == ipAncillaryFamilyAny {
		return true
	}
	switch family {
	case ipFamilyV4:
		return e.families&ipAncillaryFamilyV4 != 0
	case IPFamilyV6:
		return e.families&ipAncillaryFamilyV6 != 0
	default:
		return false
	}
}

func ipFamilyName(family IPFamily) string {
	switch family {
	case ipFamilyV4:
		return "IPv4"
	case IPFamilyV6:
		return "IPv6"
	default:
		return "this address family"
	}
}

func PreparedForcedIPFamily(config addrconfig.Address) IPFamily {
	switch config.Network.IPFamily {
	case addrconfig.IPFamilyIPv4:
		return ipFamilyV4
	case addrconfig.IPFamilyIPv6:
		return IPFamilyV6
	default:
		return ipFamilyUnknown
	}
}

func ipFamilyFromNetwork(network string) IPFamily {
	n := strings.ToLower(network)
	if i := strings.IndexByte(n, ':'); i >= 0 {
		n = n[:i]
	}
	switch {
	case strings.HasSuffix(n, "4"):
		return ipFamilyV4
	case strings.HasSuffix(n, "6"):
		return IPFamilyV6
	default:
		return ipFamilyUnknown
	}
}

func rejectIPAncillaryApply(e ipAncillaryEntry, family IPFamily) error {
	if e.ID == addrconfig.AncillaryNone {
		return nil
	}
	if !e.supportedOnThisPlatform() {
		return fmt.Errorf("%s: not supported on this platform", e.Canonical)
	}
	if family != ipFamilyUnknown && !e.supportedOnFamily(family) {
		return fmt.Errorf("%s: not supported on %s", e.Canonical, ipFamilyName(family))
	}
	return nil
}

// rejectUnsupportedIPAncillary fails fast when a spec requests an IP/ancillary
// option the opener group, platform, or forced IP family does not implement.
// Same combinations the CLI rejects via implementationGroups, plus Windows
// recv/ip-options/ipv6-* and IPv4/IPv6 mismatches.
func RejectUnsupportedIPAncillary(s addrconfig.Address) error {
	if AddressGroup == nil {
		return nil
	}
	group, ok := AddressGroup(s.Type)
	if !ok {
		return nil
	}
	family := PreparedForcedIPFamily(s)
	for _, action := range s.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		e, inMatrix := lookupIPAncillary(action.Ancillary)
		if !inMatrix {
			continue
		}
		name := e.Canonical
		if action.Text != "" {
			name = action.Text
		}
		if !e.supportedOnThisPlatform() {
			return fmt.Errorf("%s: option %q not supported on this platform", s.Type, name)
		}
		if !IPAncillarySupported(group, e.ID) {
			return fmt.Errorf("%s: option %q not supported with this address type", s.Type, name)
		}
		if family != ipFamilyUnknown && !e.supportedOnFamily(family) {
			return fmt.Errorf("%s: option %q not supported on %s", s.Type, name, ipFamilyName(family))
		}
	}
	return nil
}

func ancillaryRecvRequested(s addrconfig.Address) bool {
	last := make(map[addrconfig.AncillaryOption]int)
	for _, action := range s.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		e, ok := lookupIPAncillary(action.Ancillary)
		if !ok || e.Kind&ipAncillaryRecv == 0 {
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
