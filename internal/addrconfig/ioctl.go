package addrconfig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func decodeIoctl(o parse.Option, name string) (FileAction, error) {
	action := FileAction{Kind: FileActionIoctl, Name: o.OriginalSpelling()}
	switch name {
	case "ioctl-void":
		action.Ioctl = IoctlVoid
		value, err := requiredString(o)
		if err != nil {
			return FileAction{}, err
		}
		request, err := classicCInt(value)
		if err != nil {
			return FileAction{}, fmt.Errorf("invalid %s %q", action.Name, o.Value)
		}
		action.Request = uint32(int32(request)) // #nosec G115 -- zero-extend a validated C int request.
	case "ioctl-int", "ioctl-intp":
		action.Ioctl = IoctlInt
		if name == "ioctl-intp" {
			action.Ioctl = IoctlIntp
		}
		request, value, err := splitIoctlInt(o)
		if err != nil {
			return FileAction{}, err
		}
		action.Request, action.Value = request, value
	case "ioctl-bin":
		action.Ioctl = IoctlBin
		request, rest, err := splitIoctlRest(o, true)
		if err != nil {
			return FileAction{}, err
		}
		data, _, err := ParseDalan(rest, 'i')
		if err != nil {
			return FileAction{}, fmt.Errorf("invalid %s %q: %w", action.Name, o.Value, err)
		}
		if len(data) == 0 {
			return FileAction{}, fmt.Errorf("invalid %s %q (empty dalan value)", action.Name, o.Value)
		}
		action.Request, action.Bytes = request, data
	case "ioctl-string":
		action.Ioctl = IoctlString
		request, value, err := splitIoctlRest(o, false)
		if err != nil {
			return FileAction{}, err
		}
		action.Request, action.Text = request, value
	default:
		return FileAction{}, fmt.Errorf("unknown ioctl option %q", action.Name)
	}
	return action, nil
}

func splitIoctlInt(o parse.Option) (uint32, int, error) {
	request, rest, err := splitIoctlRest(o, true)
	if err != nil {
		return 0, 0, err
	}
	number, err := classicCInt(rest)
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
	request, err := classicCInt(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	rest := parts[1]
	if trim {
		rest = strings.TrimSpace(rest)
	}
	return uint32(int32(request)), rest, nil // #nosec G115 -- zero-extend a validated C int request.
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
	return int(int32(u)), nil // #nosec G115 -- preserve a C int two's-complement bit pattern.
}
