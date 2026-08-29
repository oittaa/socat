package xio

import (
	"sort"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// optionUnrestricted is true when the option is accepted on every
// address type (empty required caps, or process/appl tokens).
func optionUnrestricted(optGroups []string) bool {
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

// OptionCapsFor returns the capability tokens an option requires.
// The given spelling is looked up first so names such as ipv6-join-group
// keep their own caps; only unknown nicknames fall back to
// parse.CanonicalOptionName (o-append → append).
func OptionCapsFor(optionName string) ([]string, bool) {
	name := strings.ToLower(strings.TrimSpace(optionName))
	if name == "" {
		return nil, false
	}
	if groups, ok := optionRequiredCaps[name]; ok {
		return groups, true
	}
	canon := parse.CanonicalOptionName(name)
	if canon != name {
		if groups, ok := optionRequiredCaps[canon]; ok {
			return groups, true
		}
	}
	return nil, false
}

// TermiosOptionNames returns option spellings whose required caps include
// termios. Used to recognize TERMIOS options on platforms that reject them
// instead of applying termios.
func TermiosOptionNames() []string {
	var out []string
	for name, groups := range optionRequiredCaps {
		for _, g := range groups {
			if g == CapTermios {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// AddressAllowsOption reports whether optionName is in scope for addrType
// using registered address capabilities and OptionCapsFor.
func AddressAllowsOption(addrType, optionName string) bool {
	reg, ok := AddressRegistrationForType(addrType)
	if !ok {
		return false
	}
	optGroups, ok := OptionCapsFor(optionName)
	if !ok {
		return false
	}
	if optionUnrestricted(optGroups) {
		return true
	}
	return OptionCapsAllowed(reg.OptionCaps, optGroups)
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
// optionName should be the original spelling (parse.Option.OriginalSpelling).
// Extra allow-lists (TLS on PROXY, WebSocket path, …) can still accept a
// combination the capability filter would reject. Go-only options use address
// group/type/cap restrictions as declared in the option table.
func OptionSupportedOnAddress(reg AddressRegistration, optionName string, goGroups, goTypes, goCaps []string) bool {
	if optGroups, ok := OptionCapsFor(optionName); ok {
		if optionUnrestricted(optGroups) || OptionCapsAllowed(reg.OptionCaps, optGroups) {
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
