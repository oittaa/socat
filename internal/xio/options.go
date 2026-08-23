package xio

import (
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// optionValueAny returns the last occurrence across canonical and alias names.
func optionValueAny(s parse.Spec, names ...string) (string, bool) {
	for i := len(s.Options) - 1; i >= 0; i-- {
		for _, name := range names {
			if strings.EqualFold(s.Options[i].Name, name) {
				return s.OptionValue(s.Options[i].Name, ""), true
			}
		}
	}
	return "", false
}

func optionBoolAny(s parse.Spec, names ...string) (bool, bool) {
	value, ok := optionValueAny(s, names...)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off":
		return false, true
	default:
		return true, true
	}
}
