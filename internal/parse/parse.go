// Package parse implements classic socat address specification parsing.
package parse

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Option is a single address option (keyword or keyword=value).
type Option struct {
	Name  string
	Value string // empty if flag-style
	Has   bool   // true if =value was present (even if empty)
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

// ParseChannel parses one command-line address argument into a Channel.
func ParseChannel(s string) (Channel, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Channel{}, fmt.Errorf("empty address")
	}

	// Dual address: left!!right (not inside quotes/parens — handled by splitDual)
	left, right, ok := splitDual(s)
	if ok {
		ls, err := ParseSpec(left)
		if err != nil {
			return Channel{}, fmt.Errorf("dual left: %w", err)
		}
		rs, err := ParseSpec(right)
		if err != nil {
			return Channel{}, fmt.Errorf("dual right: %w", err)
		}
		return Channel{
			Dual: &Dual{Left: ls, Right: rs, Raw: s},
			Raw:  s,
		}, nil
	}

	spec, err := ParseSpec(s)
	if err != nil {
		return Channel{}, err
	}
	return Channel{Single: &spec, Raw: s}, nil
}

// ParseSpec parses a single (non-dual) address specification.
func ParseSpec(s string) (Spec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Spec{}, fmt.Errorf("empty address")
	}
	if err := checkBalancedQuotes(s); err != nil {
		return Spec{}, err
	}

	// Implicit types
	if s == "-" {
		return Spec{Type: "STDIO", Raw: s}, nil
	}
	// STDIO with options: -,opt=val
	if strings.HasPrefix(s, "-,") {
		opts, err := splitOptions(s[2:])
		if err != nil {
			return Spec{}, err
		}
		return Spec{Type: "STDIO", Options: opts, Raw: s}, nil
	}
	if isAllDigits(s) {
		return Spec{Type: "FD", Params: []string{s}, Raw: s}, nil
	}
	// Path-like without type keyword before first : or ,
	if looksLikePath(s) {
		params, opts, err := splitParamsAndOptions(s)
		if err != nil {
			return Spec{}, err
		}
		// For bare paths, the "param" section is the path (may include ':' on rare systems).
		if len(params) == 0 {
			params = []string{s}
		} else if len(params) > 1 {
			// rejoin if colon appeared in path before options
			params = []string{strings.Join(params, ":")}
		}
		return Spec{Type: "GOPEN", Params: params, Options: opts, Raw: s}, nil
	}

	// TYPE:params,options  or  TYPE,options  or just TYPE
	typeName, rest := splitType(s)
	if typeName == "" {
		return Spec{}, fmt.Errorf("missing address type in %q", s)
	}

	params, opts, err := splitParamsAndOptions(rest)
	if err != nil {
		return Spec{}, err
	}

	return Spec{
		Type:    strings.ToUpper(typeName),
		Params:  params,
		Options: opts,
		Raw:     s,
	}, nil
}

// OptionNamed returns the option with the given name (case-insensitive), if any.
func (s Spec) OptionNamed(name string) (Option, bool) {
	name = normalizeOptionName(name)
	for _, o := range s.Options {
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

func splitDual(s string) (left, right string, ok bool) {
	// Find !! outside of quotes/brackets
	depthParen, depthBrace, depthBracket := 0, 0, 0
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '(':
			depthParen++
		case ')':
			if depthParen > 0 {
				depthParen--
			}
		case '{':
			depthBrace++
		case '}':
			if depthBrace > 0 {
				depthBrace--
			}
		case '[':
			depthBracket++
		case ']':
			if depthBracket > 0 {
				depthBracket--
			}
		case '!':
			if depthParen == 0 && depthBrace == 0 && depthBracket == 0 &&
				i+1 < len(s) && s[i+1] == '!' {
				return s[:i], s[i+2:], true
			}
		}
	}
	return "", "", false
}

func splitType(s string) (typeName, rest string) {
	// TYPE is up to first : or , (outside nesting) — but TYPE itself has no nesting
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ':':
			return s[:i], s[i+1:]
		case ',':
			return s[:i], s[i:] // rest starts with comma → no params
		}
	}
	return s, ""
}

// splitParamsAndOptions splits "p1:p2,opt,opt=val" into params and options.
// If s starts with ',', there are no params.
func splitParamsAndOptions(s string) (params []string, opts []Option, err error) {
	if s == "" {
		return nil, nil, nil
	}

	// Find first comma at depth 0 that starts the options section.
	// Params use ':' separators; options use ','.
	// Classic: TCP:host:port,reuseaddr,bind=1.2.3.4
	optStart := findOptionsStart(s)
	var paramPart, optPart string
	if optStart < 0 {
		paramPart = s
	} else {
		paramPart = s[:optStart]
		optPart = s[optStart+1:] // skip comma
	}

	if paramPart != "" {
		params, err = splitColonParams(paramPart)
		if err != nil {
			return nil, nil, err
		}
	}
	if optPart != "" {
		opts, err = splitOptions(optPart)
		if err != nil {
			return nil, nil, err
		}
	}
	return params, opts, nil
}

// findOptionsStart returns index of the comma that begins options, or -1.
// For GOPEN paths like /tmp/foo,bar=1 the first comma starts options.
// For TCP:h:p,opt the comma after params starts options.
// We treat the first top-level comma as start of options.
func findOptionsStart(s string) int {
	return indexTopLevel(s, ',')
}

func splitColonParams(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var parts []string
	start := 0
	depthParen, depthBrace, depthBracket := 0, 0, 0
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '(':
			depthParen++
		case ')':
			if depthParen > 0 {
				depthParen--
			}
		case '{':
			depthBrace++
		case '}':
			if depthBrace > 0 {
				depthBrace--
			}
		case '[':
			depthBracket++
		case ']':
			if depthBracket > 0 {
				depthBracket--
			}
		case ':':
			if depthParen == 0 && depthBrace == 0 && depthBracket == 0 {
				parts = append(parts, unquote(s[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, unquote(s[start:]))
	return parts, nil
}

func splitOptions(s string) ([]Option, error) {
	if s == "" {
		return nil, nil
	}
	var opts []Option
	start := 0
	depthParen, depthBrace, depthBracket := 0, 0, 0
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i <= len(s); i++ {
		atEnd := i == len(s)
		c := byte(0)
		if !atEnd {
			c = s[i]
		}
		if !atEnd {
			if escape {
				escape = false
				continue
			}
			if c == '\\' && !inSingle {
				escape = true
				continue
			}
			if inSingle {
				if c == '\'' {
					inSingle = false
				}
				continue
			}
			if inDouble {
				if c == '"' {
					inDouble = false
				}
				continue
			}
			switch c {
			case '\'':
				inSingle = true
				continue
			case '"':
				inDouble = true
				continue
			case '(':
				depthParen++
				continue
			case ')':
				if depthParen > 0 {
					depthParen--
				}
				continue
			case '{':
				depthBrace++
				continue
			case '}':
				if depthBrace > 0 {
					depthBrace--
				}
				continue
			case '[':
				depthBracket++
				continue
			case ']':
				if depthBracket > 0 {
					depthBracket--
				}
				continue
			}
		}
		if atEnd || (c == ',' && depthParen == 0 && depthBrace == 0 && depthBracket == 0) {
			part := strings.TrimSpace(s[start:i])
			if part != "" {
				opts = append(opts, parseOption(part))
			}
			start = i + 1
		}
	}
	return opts, nil
}

func parseOption(s string) Option {
	// name=value; first = at top level
	eq := indexTopLevel(s, '=')
	var o Option
	if eq < 0 {
		o = Option{Name: s, Has: false}
	} else {
		o = Option{
			Name:  s[:eq],
			Value: unquote(s[eq+1:]),
			Has:   true,
		}
	}
	o.Name = normalizeOptionName(o.Name)
	return o
}

// normalizeOptionName maps classic aliases (so-*, o-*, etc.) to canonical names.
func normalizeOptionName(name string) string {
	n := strings.ToLower(name)
	aliases := map[string]string{
		"so-reuseaddr":       "reuseaddr",
		"so-reuseport":       "reuseport",
		"ipv6-join-group":    "ip-add-membership",
		"bind-tempname":      "unix-bind-tempname",
		"proxyauth":          "proxy-authorization",
		"proxyauthfile":      "proxy-authorization-file",
		"so-keepalive":       "keepalive",
		"so-bindtodevice":    "bindtodevice",
		"so-broadcast":       "broadcast",
		"so-rcvbuf":          "rcvbuf",
		"so-sndbuf":          "sndbuf",
		"so-rcvtimeo":        "rcvtimeo",
		"so-sndtimeo":        "sndtimeo",
		"tcp-nodelay":        "nodelay",
		"tcp-keepalive":      "keepalive",
		"o-nonblock":         "nonblock",
		"o-append":           "append",
		"o-trunc":            "trunc",
		"o-creat":            "creat",
		"o-excl":             "excl",
		"o-rdonly":           "rdonly",
		"o-wronly":           "wronly",
		"o-ndelay":           "nonblock",
		"sp":                 "sourceport",
		"sourceport":         "sourceport",
		"wait-slave":         "pty-wait-slave",
		"waitslave":          "pty-wait-slave",
		"pty-intervall":      "pty-interval",
		"winsz":              "tiocswinsz",
		"tiocsctty":          "ctty",
		"posixmq-priority":   "mq-prio",
		"posixmq-flush":      "mq-flush",
		"posixmq-maxmsg":     "mq-maxmsg",
		"posixmq-msgsize":    "mq-msgsize",
		"openssl-capath":     "capath",
		"tls-capath":         "capath",
		"openssl-commonname": "commonname",
		"tls-commonname":     "commonname",
		"openssl-snihost":    "snihost",
		"tls-snihost":        "snihost",
		"openssl-no-sni":     "nosni",
		"tls-no-sni":         "nosni",
	}
	if c, ok := aliases[n]; ok {
		return c
	}
	return n
}

func indexTopLevel(s string, sep byte) int {
	depthParen, depthBrace, depthBracket := 0, 0, 0
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '(':
			depthParen++
		case ')':
			if depthParen > 0 {
				depthParen--
			}
		case '{':
			depthBrace++
		case '}':
			if depthBrace > 0 {
				depthBrace--
			}
		case '[':
			depthBracket++
		case ']':
			if depthBracket > 0 {
				depthBracket--
			}
		default:
			if c == sep && depthParen == 0 && depthBrace == 0 && depthBracket == 0 {
				return i
			}
		}
	}
	return -1
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return expandSlashEscapes(s[1 : len(s)-1])
		}
	}
	// Strip nesting quotes used to hide commas/colons (classic nestlex).
	// e.g. (,)[,]{,}","([),]) → (,)[,]{,},([),])
	if strings.ContainsAny(s, `"'`) {
		s = stripNestingQuotes(s)
	}
	if !strings.Contains(s, `\`) {
		return s
	}
	return expandSlashEscapes(s)
}

// stripNestingQuotes removes quote delimiter characters while keeping content.
func stripNestingQuotes(s string) string {
	var b strings.Builder
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			b.WriteByte(c)
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			b.WriteByte(c)
			continue
		}
		if !inDouble && c == '\'' {
			inSingle = !inSingle
			continue // drop delimiter
		}
		if !inSingle && c == '"' {
			inDouble = !inDouble
			continue // drop delimiter
		}
		b.WriteByte(c)
	}
	return b.String()
}

// checkBalancedQuotes returns an error if s has an unclosed quote (classic syntax error).
func checkBalancedQuotes(s string) error {
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if !inDouble && c == '\'' {
			inSingle = !inSingle
			continue
		}
		if !inSingle && c == '"' {
			inDouble = !inDouble
			continue
		}
	}
	if inSingle || inDouble {
		return fmt.Errorf("syntax error: unexpected end of address (unbalanced quote)")
	}
	return nil
}

// expandSlashEscapes handles classic \n \r \t \0 \\ and \xHH sequences.
func expandSlashEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '0':
			b.WriteByte(0)
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				var v byte
				if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &v); err == nil {
					b.WriteByte(v)
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		default:
			// keep unknown escape as the escaped char (classic-ish)
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func looksLikePath(s string) bool {
	// Classic: if '/' before first ':' or ',', assume GOPEN
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/':
			return true
		case ':', ',':
			return false
		}
	}
	return false
}

// ParseFD parses an FD number parameter.
func ParseFD(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid fd number %q", s)
	}
	return n, nil
}
