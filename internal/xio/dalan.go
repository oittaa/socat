// SOCKET address data uses quoted strings with C-style escapes ("path\0"),
// hex segments (xHHHH), and single-character forms ('c').
package xio

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ParseSocatData parses SOCKET address data:
//
//	"path\0"  double-quoted string with C-style escapes
//	\"path\0\"  same after the shell leaves backslash-quotes
//	xHHHH...  hex with a lowercase x prefix (segments may be separated by extra 'x')
//	'c'       single character only (multi-char → syntax error)
//
// Raw unquoted paths are also accepted for AF_UNIX convenience.
func ParseSocatData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	// Shell-escaped double quotes: \"...\" may remain in argv.
	if strings.HasPrefix(s, `\"`) {
		s = unescapeShellQuotes(s)
	}
	// Leading ' is a single character, not a quoted string.
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
	// Double-quoted string.
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
	// Hex form: xHHHH or xHHHHxHHHH... Only lowercase x is a type prefix.
	if s[0] == 'x' {
		var out []byte
		for _, part := range strings.Split(s, "x") {
			if part == "" {
				continue
			}
			if len(part)%2 == 1 {
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
	if s[0] == 'X' {
		return nil, fmt.Errorf("syntax error in %q", s)
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

// int and short are 32/16-bit on every supported platform. long follows
// LP64 (Unix) vs LLP64 (Windows).
const (
	sizeCInt   = 4
	sizeCShort = 2
)

const (
	dalanOK = iota
	dalanSyntax
	dalanSpace
	dalanNotType
)

// ParseDalan packs typed items at the current offset with native widths and
// endianness and no extra alignment. deflt is the default type for untyped
// numbers (setsockopt-bin uses 'i'); a successful typed item becomes the default.
// singleInt is true for exactly one native C int (bare decimal or iN only).
func ParseDalan(s string, deflt byte) (data []byte, singleInt bool, err error) {
	if deflt == 0 {
		deflt = 'i'
	}
	line := s
	items := 0
	onlyI := true
	for line != "" {
		c := line[0]
		rest := line[1:]
		out, next, rc := dalanItem(c, rest)
		switch rc {
		case dalanOK:
			data = append(data, out...)
			line = next
			deflt = c
			items++
			if c != 'i' {
				onlyI = false
			}
		case dalanSpace:
			line = rest
		case dalanNotType:
			out, next, rc = dalanItem(deflt, line)
			if rc != dalanOK || next == line {
				return nil, false, fmt.Errorf("syntax error in %q", s)
			}
			data = append(data, out...)
			line = next
			items++
			if deflt != 'i' {
				onlyI = false
			}
		default:
			return nil, false, fmt.Errorf("syntax error in %q", s)
		}
	}
	singleInt = items == 1 && onlyI && len(data) == sizeCInt
	return data, singleInt, nil
}

func dalanItem(c byte, line string) (out []byte, rest string, rc int) {
	switch c {
	case ' ', '\t', '\r', '\n':
		return nil, line, dalanSpace
	case '"':
		payload, next, err := parseDalanString(`"` + line)
		if err != nil {
			return nil, line, dalanSyntax
		}
		return payload, next, dalanOK
	case '\'':
		return dalanChar(line)
	case 'x':
		return dalanHex(line)
	case 'l':
		return dalanNumber(line, sizeCLong, true)
	case 'L':
		return dalanNumber(line, sizeCLong, false)
	case 'i':
		return dalanNumber(line, sizeCInt, true)
	case 'I':
		return dalanNumber(line, sizeCInt, false)
	case 's':
		return dalanNumber(line, sizeCShort, true)
	case 'S':
		return dalanNumber(line, sizeCShort, false)
	case 'b':
		// 'b' writes a signed byte then an unsigned byte. When no second
		// number starts at the remainder, the second byte is 0 without
		// advancing the input.
		first, rest, rc := dalanNumber(line, 1, true)
		if rc != dalanOK {
			return nil, line, rc
		}
		second, next, rc := dalanNumber(rest, 1, false)
		if rc != dalanOK {
			second, next = []byte{0}, rest
		}
		return append(first, second...), next, dalanOK
	case 'B':
		return dalanNumber(line, 1, false)
	default:
		return nil, line, dalanNotType
	}
}

func dalanChar(line string) ([]byte, string, int) {
	if line == "" {
		return nil, line, dalanSyntax
	}
	c := line[0]
	line = line[1:]
	if c == '\'' {
		return nil, line, dalanSyntax
	}
	if c == '\\' {
		if line == "" {
			return nil, line, dalanSyntax
		}
		c = escapeByte(line[0])
		line = line[1:]
	}
	if line == "" || line[0] != '\'' {
		return nil, line, dalanSyntax
	}
	return []byte{c}, line[1:], dalanOK
}

func dalanHex(line string) ([]byte, string, int) {
	var out []byte
	for len(line) >= 2 && isHexDigit(line[0]) {
		if !isHexDigit(line[1]) {
			return nil, line, dalanSyntax
		}
		b, err := hex.DecodeString(line[:2])
		if err != nil {
			return nil, line, dalanSyntax
		}
		out = append(out, b...)
		line = line[2:]
	}
	if len(line) > 0 && isHexDigit(line[0]) {
		return nil, line, dalanSyntax
	}
	return out, line, dalanOK
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func dalanNumber(line string, nbytes int, _ bool) ([]byte, string, int) {
	n, rest, ok := parseDalanInt(line)
	if !ok {
		return nil, line, dalanSyntax
	}
	// Two's complement packing matches C assignment into the native width.
	return appendNative(nil, uint64(n), nbytes), rest, dalanOK // #nosec G115 -- C two's-complement store
}

func parseDalanInt(line string) (int64, string, bool) {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
		i++
	}
	start := i
	if i < len(line) && (line[i] == '+' || line[i] == '-') {
		i++
	}
	digits := i
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == digits {
		return 0, line, false
	}
	n, err := strconv.ParseInt(line[start:i], 10, 64)
	if err != nil {
		u, uerr := strconv.ParseUint(line[start:i], 10, 64)
		if uerr != nil {
			return 0, line, false
		}
		return int64(u), line[i:], true // #nosec G115 -- unsigned-to-signed store
	}
	return n, line[i:], true
}

func appendNative(buf []byte, u uint64, nbytes int) []byte {
	b := make([]byte, nbytes)
	switch nbytes {
	case 1:
		b[0] = byte(u) // #nosec G115 -- truncate to the C width
	case 2:
		binary.NativeEndian.PutUint16(b, uint16(u)) // #nosec G115 -- truncate to the C width
	case 4:
		binary.NativeEndian.PutUint32(b, uint32(u)) // #nosec G115 -- truncate to the C width
	case 8:
		binary.NativeEndian.PutUint64(b, u)
	default:
		return buf
	}
	return append(buf, b...)
}
func nativeCInt(data []byte) int {
	if len(data) < sizeCInt {
		return 0
	}
	return int(int32(binary.NativeEndian.Uint32(data[:sizeCInt]))) // #nosec G115 -- C int is 32-bit two's complement
}
