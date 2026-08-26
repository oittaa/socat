package parse

import (
	"strings"
)

// Option is a single address option (keyword or keyword=value).
type Option struct {
	Name     string // canonical runtime name after alias folding
	Spelling string // original keyword, lowercased (so-type, o-append)
	Value    string // empty if flag-style
	Has      bool   // true if =value was present (even if empty)
}

// OriginalSpelling returns the keyword as specified, or Name if Spelling is unset.
func (o Option) OriginalSpelling() string {
	if o.Spelling != "" {
		return o.Spelling
	}
	return o.Name
}

// Spec is a single address specification.
type Spec struct {
	Type    string   // uppercase keyword, e.g. "TCP4", "STDIO", "GOPEN"
	Params  []string // positional parameters after TYPE:
	Options []Option
	Raw     string // original text (for errors)
}

// Dual is a dual-type address: read from Left, write to Right.
type Dual struct {
	Left  Spec
	Right Spec
	Raw   string
}

// Channel is either a single Spec or a Dual address.
type Channel struct {
	Single *Spec
	Dual   *Dual
	Raw    string
}

// IsDual reports whether this channel uses dual addressing.
func (c Channel) IsDual() bool { return c.Dual != nil }

// OptionNamed returns the option with the given name (case-insensitive), if any.
func (s Spec) OptionNamed(name string) (Option, bool) {
	name = normalizeOptionName(name)
	// Classic socat applies options in command-line order, so a later option
	// overrides an earlier one. Scan backwards to preserve that behavior even
	// when aliases normalize to the same canonical name.
	for i := len(s.Options) - 1; i >= 0; i-- {
		o := s.Options[i]
		if normalizeOptionName(o.Name) == name {
			return o, true
		}
	}
	return Option{}, false
}

// HasOption reports whether a flag-style or valued option is present.
func (s Spec) HasOption(name string) bool {
	_, ok := s.OptionNamed(name)
	return ok
}

// OptionValue returns the value of a named option, or def if missing.
func (s Spec) OptionValue(name, def string) string {
	o, ok := s.OptionNamed(name)
	if !ok {
		return def
	}
	if !o.Has {
		return "1" // flag present
	}
	return o.Value
}

// BoolOption returns whether an option is set truthily.
// Classic: bare flag → true; =0/false/no/off → false; empty value (=) → false
// (so-reuseaddr= disables SO_REUSEADDR).
func (s Spec) BoolOption(name string) bool {
	o, ok := s.OptionNamed(name)
	if !ok {
		return false
	}
	if !o.Has {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	if v == "" {
		return false
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}
