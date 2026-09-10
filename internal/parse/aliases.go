package parse

import "github.com/oittaa/socat/internal/optionmeta"

// normalizeOptionName maps parser aliases onto canonical names.
func normalizeOptionName(name string) string {
	return optionmeta.ParserCanonical(name)
}

// CanonicalOptionName resolves parser aliases onto the canonical spelling
// implementations look up. Public-only aliases are left unchanged.
func CanonicalOptionName(name string) string {
	return normalizeOptionName(name)
}
