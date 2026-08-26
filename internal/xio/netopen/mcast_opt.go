package netopen

import (
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// membershipJoinSpec returns the ip-add-membership / ipv6-join-group value.
// Parse no longer folds ipv6-join-group onto ip-add-membership (classic groups
// differ: IP6 vs IP4+IP6, tag-1.8.1.3 / 12c08bf), so runtime must read both.
func membershipJoinSpec(s parse.Spec) string {
	hasIP := s.HasOption("ip-add-membership")
	hasV6 := s.HasOption("ipv6-join-group")
	if !hasIP && !hasV6 {
		return ""
	}
	for i := len(s.Options) - 1; i >= 0; i-- {
		switch strings.ToLower(s.Options[i].Name) {
		case "ip-add-membership", "ipv6-join-group":
			if s.Options[i].Has {
				return s.Options[i].Value
			}
			return "1"
		}
	}
	if v := s.OptionValue("ip-add-membership", ""); v != "" {
		return v
	}
	return s.OptionValue("ipv6-join-group", "")
}
