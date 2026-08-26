// Package parse implements classic socat address specification parsing.
package parse

import (
	"fmt"
	"strings"
	"unicode"
)

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
		params, opts, err := splitParamsAndOptions(s, true)
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

	params, opts, err := splitParamsAndOptions(rest, pathParamType(typeName))
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
func splitParamsAndOptions(s string, pathParam bool) (params []string, opts []Option, err error) {
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
		params, err = splitColonParams(paramPart, pathParam)
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

func splitColonParams(s string, pathParam bool) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	// File-system and UNIX-domain address types take one path parameter. Keeping
	// it intact supports drive-relative paths (C:foo), alternate data streams,
	// and ordinary colons in Unix filenames.
	if pathParam {
		return []string{unquote(s, true)}, nil
	}
	var parts []string
	start := 0
	sc := NewSpecScanner(s, true)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls == ClassTop && c == ':' {
			if isWindowsDriveColon(s, start, sc.Pos()-1) {
				continue
			}
			parts = append(parts, unquote(s[start:sc.Pos()-1], false))
			start = sc.Pos()
		}
	}
	parts = append(parts, unquote(s[start:], false))
	return parts, nil
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
			part := strings.TrimSpace(s[start : sc.Pos()-1])
			if part != "" {
				opts = append(opts, parseOption(part))
			}
			start = sc.Pos()
		}
	}
	part := strings.TrimSpace(s[start:])
	if part != "" {
		opts = append(opts, parseOption(part))
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
		name := normalizeOptionName(s[:eq])
		o = Option{
			Name:  name,
			Value: unquote(s[eq+1:], pathOption(name)),
			Has:   true,
		}
	}
	o.Name = normalizeOptionName(o.Name)
	return o
}

// optionAliases is immutable after initialization and safe for concurrent reads.
// Keeping it out of normalizeOptionName avoids rebuilding the table on every
// option parse and lookup.
var optionAliases = map[string]string{
	"so-reuseaddr":       "reuseaddr",
	"so-reuseport":       "reuseport",
	"ipv6-join-group":    "ip-add-membership",
	"bind-tempname":      "unix-bind-tempname",
	"proxyauth":          "proxy-authorization",
	"proxyauthfile":      "proxy-authorization-file",
	"so-keepalive":       "keepalive",
	"so-bindtodevice":    "bindtodevice",
	"if":                 "bindtodevice",
	"interface":          "bindtodevice",
	"so-broadcast":       "broadcast",
	"so-rcvbuf":          "rcvbuf",
	"so-sndbuf":          "sndbuf",
	"so-rcvbuf-late":     "rcvbuf-late",
	"so-sndbuf-late":     "sndbuf-late",
	"so-rcvtimeo":        "rcvtimeo",
	"so-sndtimeo":        "sndtimeo",
	"so-type":            "socktype",
	"tcp-nodelay":        "nodelay",
	"tcp-keepalive":      "keepalive",
	"o-nonblock":         "nonblock",
	"o-append":           "append",
	"direct":             "o-direct",
	"o_direct":           "o-direct",
	"ext2-noatime":       "fs-noatime",
	"ext3-noatime":       "fs-noatime",
	"o-trunc":            "trunc",
	"o-creat":            "creat",
	"o-excl":             "excl",
	"o-rdonly":           "rdonly",
	"o-wronly":           "wronly",
	"delete":             "unlink",
	"remove":             "unlink",
	"uid-e":              "user-early",
	"gid-e":              "group-early",
	"o-ndelay":           "nonblock",
	"so-keepidle":        "keepidle",
	"so-keepintvl":       "keepintvl",
	"so-keepcnt":         "keepcnt",
	"tcp-keepidle":       "keepidle",
	"tcp-keepintvl":      "keepintvl",
	"tcp-keepcnt":        "keepcnt",
	"listen-timeout":     "accept-timeout",
	"ignoreof":           "ignoreeof",
	"ipttl":              "ip-ttl",
	"iptos":              "ip-tos",
	"sp":                 "sourceport",
	"sourceport":         "sourceport",
	"addrconfig":         "ai-addrconfig",
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
	"cipher":             "ciphers",
	"openssl-cipherlist": "ciphers",
	"sockopt-listen":     "setsockopt-listen",
	"f-setlk-wr":         "setlk",
	"f-setlkw-wr":        "setlkw",
	"f-setlk-rd":         "setlk-rd",
	"f-setlkw-rd":        "setlkw-rd",
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

func indexTopLevel(s string, sep byte) int {
	return NewSpecScanner(s, true).FindTop(sep)
}

func unquote(s string, pathValue bool) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
			if pathValue && looksLikeWindowsPath(s) {
				return s
			}
			return expandSlashEscapes(s)
		}
	}
	// Strip nesting quotes used to hide commas/colons (classic nestlex).
	// e.g. (,)[,]{,}","([),]) → (,)[,]{,},([),])
	if strings.ContainsAny(s, `"'`) {
		s = stripNestingQuotes(s)
	}
	// Native Windows paths keep backslashes; \t \0 \xHH would corrupt Temp\ and \001.
	if pathValue && looksLikeWindowsPath(s) {
		return s
	}
	if !strings.Contains(s, `\`) {
		return s
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

// checkBalancedQuotes returns an error if s has an unclosed quote (classic syntax error).
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
