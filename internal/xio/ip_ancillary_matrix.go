package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// IPAncillaryKind is a bitmask of runtime effects this port actually implements
// for one IP/ancillary option. Combinations that are not listed are rejected
// instead of being accepted as no-ops.
type IPAncillaryKind uint8

const (
	// IPAncillaryRecv requires a ReadMsg/ReadMsgUDP/ReadMsgIP path that
	// surfaces cmsg data (SOCAT_* / session env).
	IPAncillaryRecv IPAncillaryKind = 1 << iota
	// IPAncillarySend applies a send-side setsockopt (TTL, TOS, hop limit, …).
	IPAncillarySend
)

// IPAncillaryEntry is one row of the address-family × option runtime matrix.
// Classic GROUP_* metadata (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree)
// is broader — SOCKET and SOCK_IP match TCP, UNIX, QUIC, and generic sockets —
// but this port only honors the groups listed here.
type IPAncillaryEntry struct {
	Canonical string
	Aliases   []string
	Kind      IPAncillaryKind
	Groups    []string
}

// ipAncillaryRecvGroups are datagram address families whose I/O path uses
// ReadMsg when a recv ancillary option is set.
var ipAncillaryRecvGroups = []string{GroupUDP, GroupRawIP}

// ipAncillarySendGroups are families that apply send-side IP socket options
// on the underlying INET fd (TCP/SCTP/TLS/WS/PROXY via applyIPTTLTOS;
// UDP/raw IP/QUIC via ApplyIPSendOpts).
var ipAncillarySendGroups = []string{
	GroupUDP, GroupRawIP, GroupTCP, GroupSCTP,
	GroupTLS, GroupWebSocket, GroupProxy, GroupQUIC,
}

// ipAncillaryMatrix is the authoritative runtime support table. CLI
// implementationGroups are derived from it; OpenSpec rejects the same
// combinations. Recv ancillary is not advertised on TCP or QUIC: stream TCP
// and quic-go's PacketConn do not surface cmsgs. Send-side options are
// advertised on QUIC because they are applied to the transport UDP fd.
//
// Not listed, and therefore not advertised: ip-recverr, ip-recvdstaddr,
// ip-retopts, ipv6-recverr, ipv6-recvhopopts, ipv6-recvdstopts, and the
// other classic SOCK_IP flags this port does not implement.
var ipAncillaryMatrix = []IPAncillaryEntry{
	{Canonical: "so-timestamp", Aliases: []string{"timestamp"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ip-pktinfo", Aliases: []string{"pktinfo"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ip-recvttl", Aliases: []string{"recvttl"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ip-recvtos", Aliases: []string{"recvtos"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ip-recvopts", Aliases: []string{"recvopts"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ipv6-recvpktinfo", Aliases: []string{"recvpktinfo"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ipv6-recvhoplimit", Aliases: []string{"recvhoplimit"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},
	{Canonical: "ipv6-recvtclass", Aliases: []string{"recvtclass"}, Kind: IPAncillaryRecv, Groups: ipAncillaryRecvGroups},

	{Canonical: "ip-ttl", Aliases: []string{"ttl", "ipttl"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups},
	{Canonical: "ip-tos", Aliases: []string{"tos", "iptos"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups},
	{Canonical: "ip-options", Kind: IPAncillarySend, Groups: ipAncillarySendGroups},
	{Canonical: "ipv6-unicast-hops", Aliases: []string{"unicast-hops"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups},
	{Canonical: "ipv6-tclass", Aliases: []string{"tclass"}, Kind: IPAncillarySend, Groups: ipAncillarySendGroups},
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
// one option. Unknown names return nil (no extra restriction).
func IPAncillaryImplementationGroups(optionName string) []string {
	e, ok := lookupIPAncillary(optionName)
	if !ok {
		return nil
	}
	return append([]string(nil), e.Groups...)
}

// IPAncillarySupported reports whether this port implements optionName on the
// address help-section group. Options that are not in the matrix are unrestricted
// here (classic GROUP_* / addressTypes still apply).
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

// RejectUnsupportedIPAncillary fails fast when a spec requests an IP/ancillary
// option this opener group does not implement. Same combinations the CLI
// rejects via implementationGroups.
func RejectUnsupportedIPAncillary(s parse.Spec) error {
	reg, ok := AddressRegistrationForType(s.Type)
	if !ok {
		return nil
	}
	for _, option := range s.Options {
		name := option.Name
		if name == "" {
			name = option.OriginalSpelling()
		}
		if IPAncillarySupported(reg.Group, name) {
			continue
		}
		return fmt.Errorf("%s: option %q not supported with this address type", s.Type, option.Name)
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

// ancillaryRecvInt returns the TYPE_INT value classic OFUNC_SOCKOPT would
// pass to setsockopt. Presence without a value is 1; =0/false/no/off is 0.
func ancillaryRecvInt(s parse.Spec, names ...string) (int, bool, error) {
	for _, name := range names {
		o, ok := s.OptionNamed(name)
		if !ok {
			continue
		}
		if !o.Has {
			return 1, true, nil
		}
		v := strings.ToLower(strings.TrimSpace(o.Value))
		switch v {
		case "", "0", "false", "no", "off":
			return 0, true, nil
		case "1", "true", "yes", "on":
			return 1, true, nil
		}
		n, err := ParseIntAny(o.Value)
		if err != nil {
			return 0, true, fmt.Errorf("%s: %w", name, err)
		}
		return n, true, nil
	}
	return 0, false, nil
}
