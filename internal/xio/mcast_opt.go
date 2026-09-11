package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// membershipFamily selects the sockopt, not the multicast address family.
// ip-add-membership is always IP_ADD_MEMBERSHIP; ipv6-join-group is always
// IPV6_JOIN_GROUP.
type membershipFamily int

const (
	membershipFamilyIPv4 membershipFamily = iota + 1
	membershipFamilyIPv6
)

type membershipJoin struct {
	family membershipFamily
	spec   string
	name   string // canonical option name used in errors
}

func (j membershipJoin) optionName() string {
	if j.name != "" {
		return j.name
	}
	if j.family == membershipFamilyIPv6 {
		return "ipv6-join-group"
	}
	return "ip-add-membership"
}

func membershipFamilyOf(o parse.Option) (membershipFamily, string, bool) {
	// Original spelling is authoritative because these two options have
	// different socket families. This also keeps manually constructed
	// Specs safe if Name was folded incorrectly.
	if family, name, ok := membershipFamilyName(o.OriginalSpelling()); ok {
		return family, name, true
	}
	return membershipFamilyName(o.Name)
}

func membershipFamilyName(name string) (membershipFamily, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-add-membership", "add-membership", "ip-membership", "membership":
		return membershipFamilyIPv4, "ip-add-membership", true
	case "ipv6-join-group", "ipv6-add-membership", "join-group":
		return membershipFamilyIPv6, "ipv6-join-group", true
	default:
		return 0, "", false
	}
}

type multicastNamedKind int

const (
	multicastNamedIf multicastNamedKind = iota + 1
	multicastNamedLoop
	multicastNamedTTL
	multicastNamedIPv6Loop
)

func multicastNamedOf(o parse.Option) (multicastNamedKind, string, bool) {
	if kind, name, ok := multicastNamedName(o.OriginalSpelling()); ok {
		return kind, name, true
	}
	return multicastNamedName(o.Name)
}

func multicastNamedName(name string) (multicastNamedKind, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-multicast-if", "multicast-if":
		return multicastNamedIf, "ip-multicast-if", true
	case "ip-multicast-loop", "multicast-loop", "mcloop", "ipmulticastloop", "multicastloop":
		return multicastNamedLoop, "ip-multicast-loop", true
	case "ip-multicast-ttl", "multicast-ttl", "ipmulticastttl", "multicastttl":
		return multicastNamedTTL, "ip-multicast-ttl", true
	case "ipv6-multicast-loop", "ipv6-mcloop", "mcloop6":
		return multicastNamedIPv6Loop, "ipv6-multicast-loop", true
	default:
		return 0, "", false
	}
}

func sourceMembershipName(name string) (membershipFamily, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-add-source-membership", "add-source-membership", "source-membership":
		return membershipFamilyIPv4, "ip-add-source-membership", true
	case "ipv6-join-source-group", "ipv6-add-source-membership", "join-source-group":
		return membershipFamilyIPv6, "ipv6-join-source-group", true
	default:
		return 0, "", false
	}
}

func mtuDiscoveryName(name string) (membershipFamily, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-mtu-discover", "mtudiscover", "ipmtudiscover":
		return membershipFamilyIPv4, "ip-mtu-discover", true
	case "ipv6-mtu-discover", "mtudiscover6":
		return membershipFamilyIPv6, "ipv6-mtu-discover", true
	default:
		return 0, "", false
	}
}

// NeedRecvErr reports whether the spec enables IP_RECVERR (Linux).
func NeedRecvErr(s addrconfig.Address) bool {
	config := s
	var n int
	var set bool
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionRecvErr && action.Text == "ip-recverr" {
			n = action.Number
			set = true
		}
	}
	return set && n != 0
}

// RejectUnsupportedRecvErr fails fast for ipv6-recverr everywhere and for
// ip-recverr on platforms that do not implement IP_RECVERR.
func RejectUnsupportedRecvErr(s addrconfig.Address) error {
	config := s
	typ := config.Type
	if typ == "" {
		typ = s.Type
	}
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionRecvErr {
			continue
		}
		name := action.Text
		if name == "ip-recverr" && recvErrSupported() {
			continue
		}
		if typ == "" {
			return fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", name)
		}
		return fmt.Errorf("%s: option %q is not supported (no MSG_ERRQUEUE ReadMsg path)", typ, name)
	}
	return nil
}

// classicFlagInt: bare flag → 1; assigned value is base-0. max>=0 rejects
// values above max (bytes are 0..255).
func classicFlagInt(o parse.Option, max int) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := ParseIntAny(o.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", o.Value)
	}
	if max >= 0 && (n < 0 || n > max) {
		return 0, fmt.Errorf("invalid value %q", o.Value)
	}
	return n, nil
}
