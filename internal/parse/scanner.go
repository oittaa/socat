package parse

// ScanClass classifies one byte walked by a SpecScanner.
type ScanClass uint8

const (
	// ClassTop marks an ordinary byte at the top level: outside quotes, not
	// consumed by a backslash escape, and (when nesting is tracked) with all
	// () {} [] groups closed. Only such bytes act as separators.
	ClassTop ScanClass = iota
	// ClassSkip marks a consumed byte that is never a separator: escaped
	// characters, content inside quotes, and grouping characters themselves.
	ClassSkip
	// ClassDelim marks a quote delimiter byte (" or '). Nesting-stripping
	// drops these; everything else treats them like ClassSkip.
	ClassDelim
)

// SpecScanner walks an address specification applying the classic rules
// shared by every parser entry point: backslash escapes the next byte unless
// inside single quotes, single and double quotes toggle independently, and —
// when nesting is tracked — (), {}, [] may hide separators.
//
// It replaces several hand-rolled copies of the same loop; the exported form
// also serves packages that re-parse raw address text (classic SOCKET dalan
// forms in netopen).
type SpecScanner struct {
	s            string
	i            int // index one past the most recent Step()ed byte
	single       bool
	double       bool
	esc          bool
	paren        int
	brace        int
	bracket      int
	trackNesting bool
}

// NewSpecScanner returns a scanner over s. TrackNesting=false leaves
// grouping characters as ordinary bytes, matching the raw SOCKET address
// paths; true enables depth hiding for address-spec parsing.
func NewSpecScanner(s string, trackNesting bool) *SpecScanner {
	return &SpecScanner{s: s, trackNesting: trackNesting}
}

// Pos returns the absolute index one past the most recently consumed byte.
func (sc *SpecScanner) Pos() int { return sc.i }

// Single reports an unterminated single quote after the walk.
func (sc *SpecScanner) Single() bool { return sc.single }

// Double reports an unterminated double quote after the walk.
func (sc *SpecScanner) Double() bool { return sc.double }

// Step consumes the next byte. ok is false once the input is exhausted.
func (sc *SpecScanner) Step() (c byte, cls ScanClass, ok bool) {
	if sc.i >= len(sc.s) {
		return 0, ClassSkip, false
	}
	c = sc.s[sc.i]
	sc.i++
	switch {
	case sc.esc:
		sc.esc = false
		return c, ClassSkip, true
	case c == '\\' && !sc.single:
		sc.esc = true
		return c, ClassSkip, true
	case sc.single:
		if c == '\'' {
			sc.single = false
			return c, ClassDelim, true
		}
		return c, ClassSkip, true
	case sc.double:
		if c == '"' {
			sc.double = false
			return c, ClassDelim, true
		}
		return c, ClassSkip, true
	case !sc.double && c == '\'':
		sc.single = true
		return c, ClassDelim, true
	case !sc.single && c == '"':
		sc.double = true
		return c, ClassDelim, true
	}
	if sc.trackNesting {
		switch c {
		case '(':
			sc.paren++
			return c, ClassSkip, true
		case ')':
			if sc.paren > 0 {
				sc.paren--
			}
			return c, ClassSkip, true
		case '{':
			sc.brace++
			return c, ClassSkip, true
		case '}':
			if sc.brace > 0 {
				sc.brace--
			}
			return c, ClassSkip, true
		case '[':
			sc.bracket++
			return c, ClassSkip, true
		case ']':
			if sc.bracket > 0 {
				sc.bracket--
			}
			return c, ClassSkip, true
		}
		if sc.paren != 0 || sc.brace != 0 || sc.bracket != 0 {
			return c, ClassSkip, true
		}
	}
	return c, ClassTop, true
}

// FindTop returns the absolute index of the first top-level occurrence of
// sep, or -1.
func (sc *SpecScanner) FindTop(sep byte) int {
	for {
		c, cls, ok := sc.Step()
		if !ok {
			return -1
		}
		if cls == ClassTop && c == sep {
			return sc.i - 1
		}
	}
}
