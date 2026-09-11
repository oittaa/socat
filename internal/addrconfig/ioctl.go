package addrconfig

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func decodeIoctl(o parse.Option) (FileAction, error) {
	action := FileAction{Kind: FileActionIoctl, Name: o.OriginalSpelling()}
	var kind int
	switch optionIdentity(o) {
	case "ioctl-void":
		kind = 1
		value, err := requiredString(o)
		if err != nil {
			return FileAction{}, err
		}
		request, err := classicIoctlRequest(value)
		if err != nil {
			return FileAction{}, fmt.Errorf("invalid %s %q", action.Name, o.Value)
		}
		action.Request = request
	case "ioctl-int", "ioctl-intp":
		if optionIdentity(o) == "ioctl-int" {
			kind = 2
		} else {
			kind = 3
		}
		request, value, err := splitIoctlInt(o)
		if err != nil {
			return FileAction{}, err
		}
		action.Request, action.Value = request, value
	case "ioctl-bin":
		kind = 4
		request, rest, err := splitIoctlRest(o, true)
		if err != nil {
			return FileAction{}, err
		}
		data, err := decodeDalan(rest)
		if err != nil || len(data) == 0 {
			if err != nil {
				return FileAction{}, fmt.Errorf("invalid %s %q: %w", action.Name, o.Value, err)
			}
			return FileAction{}, fmt.Errorf("invalid %s %q (empty dalan value)", action.Name, o.Value)
		}
		action.Request, action.Bytes = request, data
	case "ioctl-string":
		kind = 5
		request, value, err := splitIoctlRest(o, false)
		if err != nil {
			return FileAction{}, err
		}
		action.Request, action.Text = request, value
	default:
		return FileAction{}, fmt.Errorf("unknown ioctl option %q", action.Name)
	}
	action.ValueKind = uint8(kind)
	return action, nil
}

func splitIoctlInt(o parse.Option) (uint32, int, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, 0, err
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid %s %q (want request:value)", o.OriginalSpelling(), o.Value)
	}
	request, err := classicIoctlRequest(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	number, err := classicCInt(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	return request, number, nil
}

func splitIoctlRest(o parse.Option, trim bool) (uint32, string, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, "", err
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid %s %q (want request:value)", o.OriginalSpelling(), o.Value)
	}
	request, err := classicIoctlRequest(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	rest := parts[1]
	if trim {
		rest = strings.TrimSpace(rest)
	}
	return request, rest, nil
}

func classicCInt(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty integer")
	}
	n, err := strconv.ParseInt(value, 0, 32)
	if err == nil {
		return int(n), nil
	}
	u, uerr := strconv.ParseUint(value, 0, 32)
	if uerr != nil {
		return 0, err
	}
	return int(int32(u)), nil
}

func classicIoctlRequest(value string) (uint32, error) {
	n, err := classicCInt(value)
	if err != nil {
		return 0, err
	}
	return uint32(int32(n)), nil
}

func decodeDalan(source string) ([]byte, error) {
	line := source
	var data []byte
	defaultKind := byte('i')
	for line != "" {
		kind, rest := line[0], line[1:]
		item, next, status := dalanItem(kind, rest)
		switch status {
		case dalanOK:
			defaultKind = kind
		case dalanSpace:
			line = rest
			continue
		case dalanNotType:
			item, next, status = dalanItem(defaultKind, line)
			if status != dalanOK || next == line {
				return nil, fmt.Errorf("syntax error in %q", source)
			}
		default:
			return nil, fmt.Errorf("syntax error in %q", source)
		}
		data = append(data, item...)
		line = next
	}
	return data, nil
}

const (
	dalanOK = iota
	dalanSyntax
	dalanSpace
	dalanNotType
)

func dalanItem(kind byte, value string) ([]byte, string, int) {
	switch kind {
	case ' ', '\t', '\r', '\n':
		return nil, value, dalanSpace
	case '"':
		data, rest, ok := dalanString(`"` + value)
		if !ok {
			return nil, value, dalanSyntax
		}
		return data, rest, dalanOK
	case '\'':
		return dalanChar(value)
	case 'x':
		return dalanHex(value)
	case 'i', 'I':
		return dalanNumber(value, 4)
	case 's', 'S':
		return dalanNumber(value, 2)
	case 'l', 'L':
		return dalanNumber(value, classicDalanLongSize)
	case 'B':
		return dalanNumber(value, 1)
	case 'b':
		first, rest, status := dalanNumber(value, 1)
		if status != dalanOK {
			return nil, value, status
		}
		second, next, status := dalanNumber(rest, 1)
		if status != dalanOK {
			second, next = []byte{0}, rest
		}
		return append(first, second...), next, dalanOK
	default:
		return nil, value, dalanNotType
	}
}

func dalanString(value string) ([]byte, string, bool) {
	if len(value) == 0 || value[0] != '"' {
		return nil, value, false
	}
	var data []byte
	for i := 1; i < len(value); i++ {
		if value[i] == '"' {
			return data, value[i+1:], true
		}
		if value[i] == '\\' {
			i++
			if i == len(value) {
				return nil, value, false
			}
			data = append(data, dalanEscape(value[i]))
			continue
		}
		data = append(data, value[i])
	}
	return nil, value, false
}

func dalanChar(value string) ([]byte, string, int) {
	if value == "" {
		return nil, value, dalanSyntax
	}
	char := value[0]
	value = value[1:]
	if char == '\'' {
		return nil, value, dalanSyntax
	}
	if char == '\\' {
		if value == "" {
			return nil, value, dalanSyntax
		}
		char = dalanEscape(value[0])
		value = value[1:]
	}
	if value == "" || value[0] != '\'' {
		return nil, value, dalanSyntax
	}
	return []byte{char}, value[1:], dalanOK
}

func dalanHex(value string) ([]byte, string, int) {
	var data []byte
	for len(value) >= 2 && isHex(value[0]) {
		if !isHex(value[1]) {
			return nil, value, dalanSyntax
		}
		part, err := hex.DecodeString(value[:2])
		if err != nil {
			return nil, value, dalanSyntax
		}
		data = append(data, part...)
		value = value[2:]
	}
	if len(value) > 0 && isHex(value[0]) {
		return nil, value, dalanSyntax
	}
	return data, value, dalanOK
}

func dalanNumber(value string, width int) ([]byte, string, int) {
	n, rest, ok := dalanInteger(value)
	if !ok {
		return nil, value, dalanSyntax
	}
	data := make([]byte, width)
	switch width {
	case 1:
		data[0] = byte(n)
	case 2:
		binary.NativeEndian.PutUint16(data, uint16(n))
	case 4:
		binary.NativeEndian.PutUint32(data, uint32(n))
	case 8:
		binary.NativeEndian.PutUint64(data, uint64(n))
	}
	return data, rest, dalanOK
}

func dalanInteger(value string) (int64, string, bool) {
	i := 0
	for i < len(value) && strings.ContainsRune(" \t\r\n", rune(value[i])) {
		i++
	}
	start := i
	if i < len(value) && (value[i] == '+' || value[i] == '-') {
		i++
	}
	digits := i
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
	}
	if i == digits {
		return 0, value, false
	}
	n, err := strconv.ParseInt(value[start:i], 10, 64)
	if err != nil {
		u, uerr := strconv.ParseUint(value[start:i], 10, 64)
		if uerr != nil {
			return 0, value, false
		}
		return int64(u), value[i:], true
	}
	return n, value[i:], true
}

func dalanEscape(value byte) byte {
	switch value {
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
		return value
	}
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}
