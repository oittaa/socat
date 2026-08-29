package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyOwnerIoctlOption applies fiosetown or siocspgrp as FIOSETOWN /
// SIOCSPGRP after socket(). Bare flag → 1; with '=' → integer. Negatives
// are process groups. The ioctl argument is a pointer to int32.
func applyOwnerIoctlOption(fd int, o parse.Option) (bool, error) {
	if !isOwnerIoctlOption(o.Name) {
		return false, nil
	}
	n, err := parseOwnerIoctlValue(o)
	if err != nil {
		return true, err
	}
	if err := applyOwnerIoctlPlatform(fd, o.Name, n); err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, nil
}

func isOwnerIoctlOption(name string) bool {
	switch name {
	case "fiosetown", "siocspgrp":
		return true
	default:
		return false
	}
}

func parseOwnerIoctlValue(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := parseClassicCInt(o.Value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", o.Name, o.Value)
	}
	return n, nil
}
