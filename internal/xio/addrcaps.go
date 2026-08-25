package xio

import "strings"

// Option capability names used by address registrations and CLI validation.
// Options that declare a capability are accepted only on addresses that
// advertise the same capability.
const (
	OptCapListen   = "listen"
	OptCapOpen     = "open"
	OptCapIPFilter = "ip-filter"
)

// DerivedOptionCaps infers option capabilities from an address keyword and
// help-section group. RegisterAddress uses this when merging AddressDesc.OptionCaps
// so new LISTEN/OPEN addresses pick up validation without a second table.
func DerivedOptionCaps(name, group string) []string {
	n := strings.ToUpper(strings.TrimSpace(name))
	var caps []string
	if strings.Contains(n, "LISTEN") {
		caps = append(caps, OptCapListen)
	}
	switch group {
	case GroupTCP, GroupUDP, GroupRawIP, GroupSCTP, GroupTLS, GroupQUIC, GroupWebSocket, GroupProxy:
		if strings.Contains(n, "LISTEN") || strings.Contains(n, "RECVFROM") {
			caps = append(caps, OptCapIPFilter)
		}
	}
	switch n {
	case "OPEN", "FILE", "GOPEN":
		caps = append(caps, OptCapOpen)
	case "POSIXMQ", "POSIXMQ-BIDIRECTIONAL", "POSIXMQ-READ", "POSIXMQ-RECEIVE",
		"POSIXMQ-RECV", "POSIXMQ-SEND", "POSIXMQ-WRITE":
		caps = append(caps, OptCapOpen)
	}
	return uniqueCaps(caps)
}

func mergeOptionCaps(derived, extra []string) []string {
	return uniqueCaps(append(append([]string{}, derived...), extra...))
}

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
	return out
}

// AddressAllowsOptionCap reports whether an address advertises cap.
func AddressAllowsOptionCap(addrCaps []string, cap string) bool {
	for _, c := range addrCaps {
		if c == cap {
			return true
		}
	}
	return false
}

// OptionCapsAllowed is true when the option is unrestricted or the address
// advertises at least one of the option's required capabilities.
func OptionCapsAllowed(addrCaps, optionCaps []string) bool {
	if len(optionCaps) == 0 {
		return true
	}
	for _, need := range optionCaps {
		if AddressAllowsOptionCap(addrCaps, need) {
			return true
		}
	}
	return false
}
