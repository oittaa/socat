package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// membershipFamily selects the classic sockopt descriptor, not the multicast
// address family. ip-add-membership is always IP_ADD_MEMBERSHIP; ipv6-join-group
// is always IPV6_JOIN_GROUP. Classic tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option tree.
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

// ApplyMembershipJoins applies every ip-add-membership / ipv6-join-group
// request in option order (classic applies each supplied option; it does not
// last-wins). PH_PASTSOCKET. No-op when none are present.
func ApplyMembershipJoins(fd int, s parse.Spec) error {
	joins := membershipJoins(s)
	if len(joins) == 0 {
		return nil
	}
	return applyMembershipJoins(fd, joins)
}

// applyMembershipOption applies one membership occurrence. Keeping this
// helper OS-neutral lets the unified PH_PASTSOCKET pass interleave multicast
// joins with generic and ancillary options in original command-line order.
func applyMembershipOption(fd int, o parse.Option) (bool, error) {
	family, name, ok := membershipFamilyOf(o)
	if !ok {
		return false, nil
	}
	join := membershipJoin{family: family, spec: o.Value, name: name}
	return true, applyMembershipJoins(fd, []membershipJoin{join})
}

// membershipJoins collects every membership option in command-line order.
// OriginalSpelling selects the classic IPv4/IPv6 descriptor; Name is the
// fallback for constructed specs that do not preserve spelling.
func membershipJoins(s parse.Spec) []membershipJoin {
	var out []membershipJoin
	for _, o := range s.Options {
		family, name, ok := membershipFamilyOf(o)
		if !ok {
			continue
		}
		out = append(out, membershipJoin{family: family, spec: o.Value, name: name})
	}
	return out
}

func membershipFamilyOf(o parse.Option) (membershipFamily, string, bool) {
	// Original spelling is authoritative because these two classic
	// descriptors have different socket families. This also keeps manually
	// constructed legacy Specs safe if Name was folded incorrectly.
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

func applyMulticastNamedOption(fd int, o parse.Option) (bool, error) {
	kind, name, ok := multicastNamedOf(o)
	if !ok {
		return false, nil
	}
	return true, applyMulticastNamedFD(fd, kind, name, o)
}

func applySourceMembershipOption(fd int, o parse.Option) (bool, error) {
	family, name, ok := sourceMembershipOf(o)
	if !ok {
		return false, nil
	}
	return true, applySourceMembershipFD(fd, family, name, o.Value)
}

func applyFreebindOption(fd int, o parse.Option) (bool, error) {
	if !isFreebindOption(o) {
		return false, nil
	}
	return true, applyFreebindFD(fd, o)
}

func applyTransparentOption(fd int, o parse.Option) (bool, error) {
	if !isTransparentOption(o) {
		return false, nil
	}
	return true, applyTransparentFD(fd, o)
}

func applyMTUDiscoveryOption(fd int, o parse.Option) (bool, error) {
	family, name, ok := mtuDiscoveryOf(o)
	if !ok {
		return false, nil
	}
	return true, applyMTUDiscoveryFD(fd, family, name, o)
}

func applyRecvErrOption(_ int, o parse.Option) (bool, error) {
	name, ok := recvErrOptionName(o)
	if !ok {
		return false, nil
	}
	return true, fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", name)
}

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

func sourceMembershipOf(o parse.Option) (membershipFamily, string, bool) {
	if family, name, ok := sourceMembershipName(o.OriginalSpelling()); ok {
		return family, name, true
	}
	return sourceMembershipName(o.Name)
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

func isFreebindOption(o parse.Option) bool {
	return freebindOptionName(o.OriginalSpelling()) || freebindOptionName(o.Name)
}

func freebindOptionName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-freebind", "freebind", "ipfreebind":
		return true
	default:
		return false
	}
}

func isTransparentOption(o parse.Option) bool {
	return transparentOptionName(o.OriginalSpelling()) || transparentOptionName(o.Name)
}

func transparentOptionName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-transparent", "transparent":
		return true
	default:
		return false
	}
}

func mtuDiscoveryOf(o parse.Option) (membershipFamily, string, bool) {
	if family, name, ok := mtuDiscoveryName(o.OriginalSpelling()); ok {
		return family, name, true
	}
	return mtuDiscoveryName(o.Name)
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

func recvErrOptionName(o parse.Option) (string, bool) {
	if name, ok := recvErrSpelling(o.OriginalSpelling()); ok {
		return name, true
	}
	return recvErrSpelling(o.Name)
}

func recvErrSpelling(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-recverr", "recverr", "iprecverr":
		return "ip-recverr", true
	case "ipv6-recverr":
		return "ipv6-recverr", true
	default:
		return "", false
	}
}

// RejectUnsupportedRecvErr fails fast for ip-recverr / ipv6-recverr.
// Classic OFUNC_SOCKOPT IP_RECVERR only enables MSG_ERRQUEUE; this port's
// ReadMsg path does not drain that queue, so advertising the option would be
// a no-op. tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official
// master af5388c898c7bb60997935aee93c223deba60c4a is the same optdesc.
func RejectUnsupportedRecvErr(s parse.Spec) error {
	for _, o := range s.Options {
		_, ok := recvErrOptionName(o)
		if !ok {
			continue
		}
		spelling := o.OriginalSpelling()
		if spelling == "" {
			spelling = o.Name
		}
		typ := s.Type
		if typ == "" {
			return fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", spelling)
		}
		return fmt.Errorf("%s: option %q is not supported (no MSG_ERRQUEUE ReadMsg path)", typ, spelling)
	}
	return nil
}

// classicFlagInt is TYPE_INT / TYPE_BYTE / TYPE_BOOL sockopt parsing:
// bare flag → 1; assigned value is base-0. max>=0 rejects values above max
// (TYPE_BYTE is 0..255). Classic tag-1.8.1.3 xioopts.c parseopts.
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
