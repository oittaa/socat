package parse

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
