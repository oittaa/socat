package parse

import "strings"

// optionAliases is immutable after initialization and safe for concurrent reads.
// Keeping it out of normalizeOptionName avoids rebuilding the table on every
// option parse and lookup. Feature-owned files call registerOptionAliases from
// init; conflicting duplicates panic.
var optionAliases = map[string]string{}

func registerOptionAliases(m map[string]string) {
	for k, v := range m {
		if prev, ok := optionAliases[k]; ok && prev != v {
			panic("duplicate option alias " + k + ": " + prev + " vs " + v)
		}
		optionAliases[k] = v
	}
}

// normalizeOptionName maps classic aliases (so-*, o-*, etc.) to canonical names.
func normalizeOptionName(name string) string {
	n := strings.ToLower(name)
	if c, ok := optionAliases[n]; ok {
		return c
	}
	return n
}

// CanonicalOptionName resolves classic aliases (so-*, o-*, tls-*, …) to the
// canonical spelling implementations look up. Exported for tooling that
// audits the option table against real consumption.
func CanonicalOptionName(name string) string {
	return normalizeOptionName(name)
}
