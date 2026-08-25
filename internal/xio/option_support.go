package xio

import (
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// ClassicOptionUnrestricted reports whether classic socat 1.8.1.3 accepts the
// option on every address type: GROUP_ADDR (empty) or GROUP_ANY (process|appl).
func ClassicOptionUnrestricted(optGroups []string) bool {
	if len(optGroups) == 0 {
		return true
	}
	for _, g := range optGroups {
		if g == "appl" || g == "process" {
			return true
		}
	}
	return false
}

// ClassicOptionGroupsFor returns the expanded GROUP_* set for an option
// keyword or nickname. Aliases such as o-append resolve to append.
func ClassicOptionGroupsFor(optionName string) ([]string, bool) {
	name := strings.ToLower(strings.TrimSpace(optionName))
	if name == "" {
		return nil, false
	}
	if groups, ok := ClassicOptionGroups[name]; ok {
		return groups, true
	}
	canon := parse.CanonicalOptionName(name)
	if canon != name {
		if groups, ok := ClassicOptionGroups[canon]; ok {
			return groups, true
		}
	}
	return nil, false
}

// ClassicAllowsOption reports whether classic socat 1.8.1.3 would accept
// optionName on addrType (parseopts group intersection).
func ClassicAllowsOption(addrType, optionName string) bool {
	optGroups, ok := ClassicOptionGroupsFor(optionName)
	if !ok {
		return false
	}
	if ClassicOptionUnrestricted(optGroups) {
		return true
	}
	return OptionCapsAllowed(ClassicAddressCaps(addrType), optGroups)
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
	// Address-type lists are the precise Go extra (TLS on PROXY, ALPN on QUIC).
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
// Classic 1.8.1.3 group intersection is authoritative for known options.
// Go extra allow-lists (TLS on PROXY, WebSocket path, …) can still accept a
// combination classic would reject. Go-only options use address group/type/cap
// restrictions exactly as declared in the option table.
func OptionSupportedOnAddress(reg AddressRegistration, optionName string, goGroups, goTypes, goCaps []string) bool {
	if optGroups, ok := ClassicOptionGroupsFor(optionName); ok {
		if ClassicOptionUnrestricted(optGroups) || OptionCapsAllowed(reg.OptionCaps, optGroups) {
			return true
		}
		return goExtraAllows(reg, goGroups, goTypes)
	}
	if !addressGroupAllowed(reg.Group, goGroups) {
		return false
	}
	if !addressTypeAllowed(reg.Name, goTypes) {
		return false
	}
	return OptionCapsAllowed(reg.OptionCaps, goCaps)
}
