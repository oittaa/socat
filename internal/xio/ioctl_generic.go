package xio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// Classic generic ioctl family (xio-fd.c opt_ioctl_* / xioopts.c
// applyopt_ioctl_generic). Baseline: https://repo.or.cz/socat.git
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba. Official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same option records and
// applyopt_ioctl_generic. GROUP_FD, PH_FD, OFUNC_IOCTL_GENERIC.
//
//	ioctl-void / ioctl  TYPE_INT         → ioctl(fd, request, NULL)
//	ioctl-int           TYPE_INT_INT     → ioctl(fd, request, int value)
//	ioctl-intp          TYPE_INT_INTP    → ioctl(fd, request, &int)
//	ioctl-bin           TYPE_INT_BIN     → ioctl(fd, request, dalan bytes)
//	ioctl-string        TYPE_INT_STRING  → ioctl(fd, request, C string)
//
// Official man ioctl-string (doc/socat.yo) says “pointer to the given string”
// then a stray “dalan form” line copied from ioctl-bin. C TYPE_INT_STRING
// strdup’s the rest after the first colon; this port follows C, not dalan.
//
// Official man ioctl-void is ioctl-void=<request>. Classic TYPE_INT without
// `=` stores 1 (ioctl request 1). This port requires a request (README).
//
// Integer fields are overflow-safe C int (strconv bitSize 32, matching
// sizeof(int) on linux/darwin/windows). Classic parseopts_table uses
// Strtoul/strtoul into int and wraps; wrapping a request number can issue
// an unintended ioctl. Reject overflow instead (README + this comment).

const classicCIntBits = 32

type ioctlGenericKind int

const (
	ioctlKindVoid ioctlGenericKind = iota
	ioctlKindInt
	ioctlKindIntp
	ioctlKindBin
	ioctlKindString
)

type ioctlGenericSpec struct {
	name   string
	kind   ioctlGenericKind
	req    uint
	intVal int
	bin    []byte
	str    string
}

// GenericIoctlOption reports whether name is a classic generic ioctl
// spelling (canonical or the ioctl → ioctl-void alias).
func GenericIoctlOption(name string) bool {
	_, ok := genericIoctlKind(name)
	return ok
}

func genericIoctlKind(name string) (ioctlGenericKind, bool) {
	switch parse.CanonicalOptionName(name) {
	case "ioctl-void":
		return ioctlKindVoid, true
	case "ioctl-int":
		return ioctlKindInt, true
	case "ioctl-intp":
		return ioctlKindIntp, true
	case "ioctl-bin":
		return ioctlKindBin, true
	case "ioctl-string":
		return ioctlKindString, true
	default:
		return 0, false
	}
}

// ValidateGenericIoctl parses a classic generic ioctl option without
// issuing ioctl(2). Shared by the CLI table and the PH_FD apply path.
func ValidateGenericIoctl(o parse.Option) error {
	_, err := parseGenericIoctl(o)
	return err
}

func parseGenericIoctl(o parse.Option) (ioctlGenericSpec, error) {
	kind, ok := genericIoctlKind(o.Name)
	if !ok {
		return ioctlGenericSpec{}, fmt.Errorf("unknown ioctl option %q", o.OriginalSpelling())
	}
	name := o.OriginalSpelling()
	out := ioctlGenericSpec{name: name, kind: kind}
	switch kind {
	case ioctlKindVoid:
		v, err := requiredIoctlValue(o)
		if err != nil {
			return ioctlGenericSpec{}, err
		}
		req, err := parseClassicCIntRequest(v)
		if err != nil {
			return ioctlGenericSpec{}, fmt.Errorf("invalid %s %q", name, o.Value)
		}
		out.req = req
		return out, nil
	case ioctlKindInt, ioctlKindIntp:
		req, payload, err := splitIoctlIntPair(o)
		if err != nil {
			return ioctlGenericSpec{}, err
		}
		out.req = req
		out.intVal = payload
		return out, nil
	case ioctlKindBin:
		req, rest, err := splitIoctlRequestRest(o, true)
		if err != nil {
			return ioctlGenericSpec{}, err
		}
		data, _, err := ParseDalan(rest, 'i')
		if err != nil {
			return ioctlGenericSpec{}, fmt.Errorf("invalid %s %q: %w", name, o.Value, err)
		}
		if len(data) == 0 {
			return ioctlGenericSpec{}, fmt.Errorf("invalid %s %q (empty dalan value)", name, o.Value)
		}
		out.req = req
		out.bin = data
		return out, nil
	case ioctlKindString:
		req, rest, err := splitIoctlRequestRest(o, false)
		if err != nil {
			return ioctlGenericSpec{}, err
		}
		out.req = req
		out.str = rest
		return out, nil
	default:
		return ioctlGenericSpec{}, fmt.Errorf("unknown ioctl option %q", name)
	}
}

func requiredIoctlValue(o parse.Option) (string, error) {
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return "", fmt.Errorf("option %q requires a value", o.OriginalSpelling())
	}
	return v, nil
}

func splitIoctlIntPair(o parse.Option) (req uint, payload int, err error) {
	name := o.OriginalSpelling()
	v, err := requiredIoctlValue(o)
	if err != nil {
		return 0, 0, err
	}
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid %s %q (want request:value)", name, o.Value)
	}
	req, err = parseClassicCIntRequest(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid %s %q", name, o.Value)
	}
	payload, err = parseClassicCInt(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid %s %q", name, o.Value)
	}
	return req, payload, nil
}

func splitIoctlRequestRest(o parse.Option, trimRest bool) (req uint, rest string, err error) {
	name := o.OriginalSpelling()
	v, err := requiredIoctlValue(o)
	if err != nil {
		return 0, "", err
	}
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid %s %q (want request:value)", name, o.Value)
	}
	req, err = parseClassicCIntRequest(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid %s %q", name, o.Value)
	}
	rest = parts[1]
	if trimRest {
		rest = strings.TrimSpace(rest)
	}
	return req, rest, nil
}

// parseClassicCInt parses classic TYPE_INT with overflow rejection.
// bitSize 32 matches C int. Signed values use ParseInt; unsigned 32-bit
// patterns (ioctl request numbers with the high bit set) use ParseUint
// and are stored as the native int with the C two's-complement bit pattern.
func parseClassicCInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty integer")
	}
	n, err := strconv.ParseInt(s, 0, classicCIntBits)
	if err == nil {
		return int(n), nil
	}
	u, uerr := strconv.ParseUint(s, 0, classicCIntBits)
	if uerr != nil {
		return 0, err
	}
	return int(int32(u)), nil // #nosec G115 -- C int two's-complement bit pattern
}

func parseClassicCIntRequest(s string) (uint, error) {
	n, err := parseClassicCInt(s)
	if err != nil {
		return 0, err
	}
	return uint(uint32(int32(n))), nil // #nosec G115 -- zero-extend 32-bit ioctl request
}
