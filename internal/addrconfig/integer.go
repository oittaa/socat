package addrconfig

import (
	"fmt"
	"strconv"
	"strings"
)

// parseDigitStrtoul parses a classic strtoul(..., 0) value. ok is false when
// the text does not start with a decimal digit, so a name can be tried instead.
// A digit-leading value must be consumed completely and fit in bitSize.
// Go-only 0b/0o forms and underscores are rejected: classic strtoul does not
// accept them, and a leftover suffix is trailing garbage rather than a name.
func parseDigitStrtoul(value string, bitSize int) (uint64, bool, error) {
	if value == "" || value[0] < '0' || value[0] > '9' {
		return 0, false, nil
	}
	if strings.ContainsRune(value, '_') || hasGoBasePrefix(value) {
		return 0, true, fmt.Errorf("invalid integer %q", value)
	}
	n, err := strconv.ParseUint(value, 0, bitSize)
	if err != nil {
		return 0, true, fmt.Errorf("invalid integer %q", value)
	}
	return n, true, nil
}

func hasGoBasePrefix(value string) bool {
	rest := value
	if rest != "" && (rest[0] == '+' || rest[0] == '-') {
		rest = rest[1:]
	}
	return strings.HasPrefix(rest, "0b") || strings.HasPrefix(rest, "0B") ||
		strings.HasPrefix(rest, "0o") || strings.HasPrefix(rest, "0O")
}

// parseNumericPort parses a uint16 with base 0, including a leading sign.
// A service name, overflow, or trailing suffix is an error. A leading minus
// is in range only for zero.
func parseNumericPort(text string) (uint16, error) {
	value := trimStrtoulSpace(text)
	negative := false
	if value != "" && (value[0] == '+' || value[0] == '-') {
		negative = value[0] == '-'
		value = value[1:]
	}
	n, numeric, err := parseDigitStrtoul(value, 16)
	if err != nil || !numeric || (negative && n != 0) {
		return 0, fmt.Errorf("invalid port %q", text)
	}
	return uint16(n), nil // #nosec G115 -- parseDigitStrtoul bitSize 16 bounds the value
}

func trimStrtoulSpace(value string) string {
	i := 0
	for i < len(value) {
		switch value[i] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			i++
		default:
			return value[i:]
		}
	}
	return ""
}
