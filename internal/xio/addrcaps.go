package xio

import "sort"

// Option capability names used by address registrations and CLI validation.
const (
	OptCapListen = "listen"
	OptCapOpen   = "open"
	OptCapRange  = "range"
)

func uniqueCaps(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// OptionCapsAllowed is true when the option is unrestricted or the address
// advertises at least one of the option's required capabilities.
func OptionCapsAllowed(addrCaps, optionCaps []string) bool {
	if len(optionCaps) == 0 {
		return true
	}
	for _, need := range optionCaps {
		for _, c := range addrCaps {
			if c == need {
				return true
			}
		}
	}
	return false
}
