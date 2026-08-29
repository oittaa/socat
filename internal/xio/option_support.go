package xio

import (
	"strings"
)

// optionUnrestricted is true when the option is accepted on every
// address type (empty required caps).
func optionUnrestricted(optCaps []string) bool {
	return len(optCaps) == 0
}

func addressGroupAllowed(group string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if group == candidate {
			return true
		}
	}
	return false
}

func addressTypeAllowed(addressType string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(addressType, candidate) {
			return true
		}
	}
	return false
}

func goExtraAllows(reg AddressRegistration, goGroups, goTypes []string) bool {
	// Address-type lists are the precise extra (TLS on PROXY, ALPN on QUIC).
	// Help-section groups are broader (TLS+WSS share a section) and are only
	// used when no type list is declared, e.g. WebSocket path/origin/protocol.
	if len(goTypes) > 0 {
		return addressTypeAllowed(reg.Name, goTypes)
	}
	if len(goGroups) > 0 {
		return addressGroupAllowed(reg.Group, goGroups)
	}
	return false
}

// OptionSupportedOnAddress is the registry-level check used by the CLI.
// goCaps are the option's required address capabilities from the option
// definition. Empty goCaps are unrestricted unless goGroups or goTypes bind
// the option to an extra allow-list (TLS on PROXY, WebSocket path, …).
func OptionSupportedOnAddress(reg AddressRegistration, goGroups, goTypes, goCaps []string) bool {
	if optionUnrestricted(goCaps) {
		if len(goTypes) == 0 && len(goGroups) == 0 {
			return true
		}
		return goExtraAllows(reg, goGroups, goTypes)
	}
	if OptionCapsAllowed(reg.OptionCaps, goCaps) {
		return true
	}
	return goExtraAllows(reg, goGroups, goTypes)
}
