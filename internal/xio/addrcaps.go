package xio

import (
	"sort"
	"strings"
)

// Option capability names used by address registrations and CLI validation.
// These match classic socat 1.8.1.3 GROUP_* atoms (see classicgroups_gen.go).
const (
	OptCapListen = "listen"
	OptCapOpen   = "open"
	OptCapRange  = "range"
)

// GoAddressClassicAlias maps Go-only or renamed address keywords onto the
// classic 1.8.1.3 addrdesc whose GROUP_* set they follow.
var GoAddressClassicAlias = map[string]string{
	"TLS":          "OPENSSL",
	"TLS-CONNECT":  "OPENSSL",
	"TLS-L":        "OPENSSL-LISTEN",
	"TLS-LISTEN":   "OPENSSL-LISTEN",
	"WS":           "TCP-CONNECT",
	"WS-CONNECT":   "TCP-CONNECT",
	"WS-L":         "TCP-LISTEN",
	"WS-LISTEN":    "TCP-LISTEN",
	"WSS":          "OPENSSL",
	"WSS-CONNECT":  "OPENSSL",
	"WSS-L":        "OPENSSL-LISTEN",
	"WSS-LISTEN":   "OPENSSL-LISTEN",
	"QUIC":         "OPENSSL-DTLS-CLIENT",
	"QUIC-CONNECT": "OPENSSL-DTLS-CLIENT",
	"QUIC-L":       "OPENSSL-DTLS-SERVER",
	"QUIC-LISTEN":  "OPENSSL-DTLS-SERVER",
}

// ClassicAddressCaps returns the expanded classic GROUP_* set for an address
// keyword, applying Go extras then classic addressnames[] aliases.
func ClassicAddressCaps(name string) []string {
	key := strings.ToUpper(strings.TrimSpace(name))
	if alias, ok := GoAddressClassicAlias[key]; ok {
		key = alias
	}
	if groups, ok := ClassicAddressGroups[key]; ok {
		return append([]string(nil), groups...)
	}
	if alias, ok := ClassicAddressAliases[key]; ok {
		if groups, ok := ClassicAddressGroups[alias]; ok {
			return append([]string(nil), groups...)
		}
	}
	return nil
}

// DerivedOptionCaps infers option capabilities from an address keyword and
// help-section group. RegisterAddress uses this when merging AddressDesc.OptionCaps
// so new addresses pick up classic 1.8.1.3 groups without a second table.
func DerivedOptionCaps(name, group string) []string {
	caps := ClassicAddressCaps(name)
	if len(caps) == 0 {
		caps = fallbackOptionCaps(name, group)
	}
	return uniqueCaps(caps)
}

// fallbackOptionCaps covers synthetic or Go-only keywords that have no classic
// addrdesc. It uses classic GROUP_* atom names so option intersection still works.
func fallbackOptionCaps(name, group string) []string {
	n := strings.ToUpper(strings.TrimSpace(name))
	var caps []string
	if strings.Contains(n, "LISTEN") {
		caps = append(caps, OptCapListen)
	}
	switch group {
	case GroupTCP, GroupUDP, GroupRawIP, GroupSCTP, GroupTLS, GroupQUIC, GroupWebSocket, GroupProxy:
		if strings.Contains(n, "LISTEN") || strings.Contains(n, "RECVFROM") {
			caps = append(caps, OptCapRange)
		}
	}
	switch group {
	case GroupTCP, GroupTLS, GroupWebSocket, GroupProxy:
		caps = append(caps, "ip-tcp")
	case GroupUDP, GroupQUIC:
		caps = append(caps, "ip-udp")
	case GroupSCTP:
		caps = append(caps, "ip-sctp")
	}
	switch n {
	case "OPEN", "FILE", "GOPEN":
		caps = append(caps, OptCapOpen)
	}
	return caps
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
