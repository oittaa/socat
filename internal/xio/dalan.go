// Classic dalan address-data parsing: quoted strings with C-style escapes
// ("path\0"), hex segments (xHHHH), and single-character forms ('c'), as
// consumed by ParseSocatData for SOCKET addresses.
package xio

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseSocatData parses classic dalan-ish SOCKET address data:
//
//	"path\0"  double-quoted string with C-style escapes
//	\"path\0\"  same after shell leaves backslash-quotes (test.sh SOCKET_CONNECT_UNIX)
//	xHHHH...  hex (segments may be separated by extra 'x')
//	'c'       single character only (classic dalan; multi-char → syntax error)
//
// Raw unquoted paths are also accepted for AF_UNIX convenience.
// Returns an error on classic-style syntax errors (DALAN_NO_SIGSEGV expects rc=1).
func ParseSocatData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	// Shell-escaped double quotes: \"...\" (classic test.sh leaves these in argv).
	if strings.HasPrefix(s, `\"`) {
		s = unescapeShellQuotes(s)
	}
	// Classic dalan: leading ' is a single character, not a quoted string.
	// SOCKET-LISTEN:1:1:'/tmp/sock' is intentionally a syntax error (DALAN_NO_SIGSEGV).
	if s[0] == '\'' {
		if len(s) < 3 || s[len(s)-1] != '\'' {
			return nil, fmt.Errorf("syntax error in %q", s)
		}
		// Exactly one character between quotes (with optional \escape).
		inner := s[1 : len(s)-1]
		if len(inner) == 1 {
			return []byte{inner[0]}, nil
		}
		if len(inner) == 2 && inner[0] == '\\' {
			return []byte{escapeByte(inner[1])}, nil
		}
		return nil, fmt.Errorf("syntax error in %q", s)
	}
	// Double-quoted string (classic UNIX SOCKET address form).
	if s[0] == '"' {
		out, rest, err := parseDalanString(s)
		if err != nil {
			return nil, err
		}
		if rest != "" {
			// trailing garbage after string — still allow concatenated x...
			more, err := ParseSocatData(rest)
			if err != nil {
				return nil, err
			}
			return append(out, more...), nil
		}
		return out, nil
	}
	// Hex form: xHHHH or xHHHHxHHHH...
	if strings.HasPrefix(s, "x") || strings.HasPrefix(s, "X") {
		var out []byte
		for _, part := range strings.Split(s, "x") {
			if part == "" {
				continue
			}
			// also handle X
			part = strings.TrimPrefix(part, "X")
			if part == "" {
				continue
			}
			if len(part)%2 == 1 {
				// classic: odd number of hex digits is a syntax error
				return nil, fmt.Errorf("syntax error in %q", s)
			}
			b, err := hex.DecodeString(part)
			if err != nil {
				return nil, fmt.Errorf("syntax error in %q", s)
			}
			out = append(out, b...)
		}
		return out, nil
	}
	// Unquoted: expand \ escapes (path convenience).
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(escapeByte(s[i]))
			continue
		}
		b.WriteByte(s[i])
	}
	return []byte(b.String()), nil
}

func unescapeShellQuotes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '"' || n == '\\' {
				b.WriteByte(n)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseDalanString parses a "..." string with escapes; returns payload and remainder.

func parseDalanString(s string) (out []byte, rest string, err error) {
	if len(s) == 0 || s[0] != '"' {
		return nil, s, fmt.Errorf("syntax error in %q", s)
	}
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '"' {
			return out, s[i+1:], nil
		}
		if c == '\\' {
			i++
			if i >= len(s) {
				return nil, "", fmt.Errorf("syntax error in %q", s)
			}
			out = append(out, escapeByte(s[i]))
			i++
			continue
		}
		out = append(out, c)
		i++
	}
	return nil, "", fmt.Errorf("syntax error in %q", s)
}

func escapeByte(c byte) byte {
	switch c {
	case '0':
		return 0
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'f':
		return '\f'
	case 'b':
		return '\b'
	case 'a':
		return '\a'
	case 'e':
		return 033
	case '\\':
		return '\\'
	case '"':
		return '"'
	case '\'':
		return '\''
	default:
		return c
	}
}
