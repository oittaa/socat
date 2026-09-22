// Package parse implements address specification parsing.
package parse

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseChannel parses one command-line address argument into a Channel.
func ParseChannel(s string) (Channel, error) {
	s = trimUnescapedSpace(s)
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
	s = trimUnescapedSpace(s)
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
		params, opts, err := splitParamsAndOptions(s, true, -1)
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

	// TYPE:params,options  or  TYPE,options  or just TYPE.
	// A colon with nothing after it is one empty parameter, so TYPE and TYPE: differ.
	typeName, rest, hadColon := splitType(s)
	if typeName == "" {
		return Spec{}, fmt.Errorf("missing address type in %q", s)
	}

	params, opts, err := splitParamsAndOptions(rest, pathParamType(typeName), socketDataIndex(typeName))
	if err != nil {
		return Spec{}, err
	}
	if hadColon && len(params) == 0 {
		params = []string{""}
	}

	return Spec{
		Type:    strings.ToUpper(typeName),
		Params:  params,
		Options: opts,
		Raw:     s,
	}, nil
}

func splitDual(s string) (left, right string, ok bool) {
	// Find !! outside of quotes/brackets
	sc := NewSpecScanner(s, true)
	for {
		c, cls, ok2 := sc.Step()
		if !ok2 {
			return "", "", false
		}
		if cls == ClassTop && c == '!' && sc.Pos() < len(s) && s[sc.Pos()] == '!' {
			return s[:sc.Pos()-1], s[sc.Pos()+1:], true
		}
	}
}

func splitType(s string) (typeName, rest string, hadColon bool) {
	// TYPE is up to first : or , (outside nesting) — but TYPE itself has no nesting
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ':':
			return s[:i], s[i+1:], true
		case ',':
			return s[:i], s[i:], false // rest starts with comma → no params
		}
	}
	return s, "", false
}

// splitParamsAndOptions splits "p1:p2,opt,opt=val" into params and options.
// If s starts with ',', there are no params.
func splitParamsAndOptions(s string, pathParam bool, dataIndex int) (params []string, opts []Option, err error) {
	if s == "" {
		return nil, nil, nil
	}

	// Find first comma at depth 0 that starts the options section.
	// Params use ':' separators; options use ','.
	// Example: TCP:host:port,reuseaddr,bind=1.2.3.4
	optStart := findOptionsStart(s)
	var paramPart, optPart string
	if optStart < 0 {
		paramPart = s
	} else {
		paramPart = s[:optStart]
		optPart = s[optStart+1:] // skip comma
	}

	if paramPart != "" {
		params, err = splitColonParams(paramPart, pathParam, dataIndex)
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

func splitColonParams(s string, pathParam bool, dataIndex int) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	// File-system and UNIX-domain address types take one path parameter. Keeping
	// it intact supports drive-relative paths (C:foo), alternate data streams,
	// and ordinary colons in Unix filenames.
	if pathParam {
		part, err := unquote(s, true)
		if err != nil {
			return nil, err
		}
		return []string{part}, nil
	}
	// SOCKET address data keeps its quotes and escapes. Domain, type, and
	// protocol are ordinary parameters.
	var parts []string
	start := 0
	index := 0
	sc := NewSpecScanner(s, dataIndex < 0)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls == ClassTop && c == ':' {
			if isWindowsDriveColon(s, start, sc.Pos()-1) {
				continue
			}
			part, err := colonParam(s[start:sc.Pos()-1], index >= dataIndex && dataIndex >= 0)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
			start = sc.Pos()
			index++
		}
	}
	part, err := colonParam(s[start:], index >= dataIndex && dataIndex >= 0)
	if err != nil {
		return nil, err
	}
	parts = append(parts, part)
	return parts, nil
}

func colonParam(value string, preserveRaw bool) (string, error) {
	if preserveRaw {
		return value, nil
	}
	return unquote(value, false)
}

func splitOptions(s string) ([]Option, error) {
	if s == "" {
		return nil, nil
	}
	var opts []Option
	start := 0
	sc := NewSpecScanner(s, true)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls == ClassTop && c == ',' {
			part := trimUnescapedSpace(s[start : sc.Pos()-1])
			if part != "" {
				opt, err := parseOption(part)
				if err != nil {
					return nil, err
				}
				opts = append(opts, opt)
			}
			start = sc.Pos()
		}
	}
	part := trimUnescapedSpace(s[start:])
	if part != "" {
		opt, err := parseOption(part)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opt)
	}
	return opts, nil
}

func parseOption(s string) (Option, error) {
	// name=value; first = at top level
	eq := indexTopLevel(s, '=')
	var rawName, rawValue string
	has := false
	if eq < 0 {
		rawName = s
	} else {
		rawName = s[:eq]
		rawValue = s[eq+1:]
		has = true
	}
	spelling := strings.ToLower(rawName)
	name := normalizeOptionName(spelling)
	o := Option{Name: name, Spelling: spelling, Has: has}
	if has {
		value, err := unquote(rawValue, pathOption(name))
		if err != nil {
			return Option{}, err
		}
		o.Value = value
	}
	return o, nil
}

func indexTopLevel(s string, sep byte) int {
	return NewSpecScanner(s, true).FindTop(sep)
}

func unquote(s string, pathValue bool) (string, error) {
	s = trimUnescapedSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
			if pathValue && looksLikeWindowsPath(s) {
				return s, nil
			}
			return expandSlashEscapes(s)
		}
	}
	// Strip nesting quotes used to hide commas/colons.
	// e.g. (,)[,]{,}","([),]) → (,)[,]{,},([),])
	if strings.ContainsAny(s, `"'`) {
		s = stripNestingQuotes(s)
	}
	// Native Windows paths keep backslashes; \t \0 \xHH would corrupt Temp\ and \001.
	if pathValue && looksLikeWindowsPath(s) {
		return s, nil
	}
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	return expandSlashEscapes(s)
}

// stripNestingQuotes removes quote delimiter characters while keeping content.
func stripNestingQuotes(s string) string {
	var b strings.Builder
	sc := NewSpecScanner(s, false)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls != ClassDelim {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// checkBalancedQuotes returns an error if s has an unclosed quote.
func checkBalancedQuotes(s string) error {
	sc := NewSpecScanner(s, false)
	for {
		if _, _, ok := sc.Step(); !ok {
			break
		}
	}
	if sc.Single() || sc.Double() {
		return fmt.Errorf("syntax error: unexpected end of address (unbalanced quote)")
	}
	return nil
}

// expandSlashEscapes resolves \0 \a \b \f \n \r \t \v \\ and \xHH.
// \xHH is exactly two hex digits. A short or non-hex \x sequence is an error.
func expandSlashEscapes(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("syntax error: trailing backslash")
		}
		i++
		switch s[i] {
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			// Vertical tab.
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case 'x':
			// \xHH is two hex digits, beyond the documented named escapes.
			if i+2 >= len(s) {
				return "", fmt.Errorf("syntax error: malformed \\x escape")
			}
			raw, err := hex.DecodeString(s[i+1 : i+3])
			if err != nil {
				return "", fmt.Errorf("syntax error: malformed \\x escape")
			}
			b.WriteByte(raw[0])
			i += 2
		default:
			// Escape the next byte, including separators such as : and ,.
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

// trimUnescapedSpace drops leading and trailing whitespace, keeping a
// trailing space that is escaped by a backslash.
func trimUnescapedSpace(s string) string {
	start := 0
	for start < len(s) {
		r, size := utf8.DecodeRuneInString(s[start:])
		if !unicode.IsSpace(r) {
			break
		}
		start += size
	}
	end := len(s)
	for end > start {
		r, size := utf8.DecodeLastRuneInString(s[:end])
		if !unicode.IsSpace(r) || escapedByte(s, end-size) {
			break
		}
		end -= size
	}
	if start == 0 && end == len(s) {
		return s
	}
	return s[start:end]
}

func escapedByte(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
