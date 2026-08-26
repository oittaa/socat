package xio

import (
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

// membershipJoins collects every membership option in command-line order.
// Canonical Name after alias fold is enough for advertised spellings
// (add-membership → ip-add-membership, join-group → ipv6-join-group).
// OriginalSpelling is also accepted so a constructed spec still classifies
// correctly if Name was not folded.
func membershipJoins(s parse.Spec) []membershipJoin {
	var out []membershipJoin
	for _, o := range s.Options {
		family, name, ok := membershipFamilyOf(o)
		if !ok {
			continue
		}
		val := o.Value
		if !o.Has {
			val = "1"
		}
		out = append(out, membershipJoin{family: family, spec: val, name: name})
	}
	return out
}

func membershipFamilyOf(o parse.Option) (membershipFamily, string, bool) {
	if family, name, ok := membershipFamilyName(o.Name); ok {
		return family, name, true
	}
	return membershipFamilyName(o.OriginalSpelling())
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
