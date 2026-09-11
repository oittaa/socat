package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

// membershipFamily selects the sockopt, not the multicast address family.
// ip-add-membership is always IP_ADD_MEMBERSHIP; ipv6-join-group is always
// IPV6_JOIN_GROUP.
type membershipFamily int

const (
	membershipFamilyIPv4 membershipFamily = iota + 1
	membershipFamilyIPv6
)

// NeedRecvErr reports whether the spec enables IP_RECVERR (Linux).
func NeedRecvErr(s addrconfig.Address) bool {
	var n int
	var set bool
	for _, action := range s.Network.Actions {
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
	typ := s.Type
	for _, action := range s.Network.Actions {
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
