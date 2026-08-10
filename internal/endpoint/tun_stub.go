//go:build !linux

package endpoint

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

func openTUN(_ context.Context, s parse.Spec, _ Mode, _ *Global) (*Opened, error) {
	if _, err := tunPositional(s); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("TUN is only supported on Linux")
}

func openINTERFACE(_ context.Context, s parse.Spec, _ Mode, _ *Global) (*Opened, error) {
	if len(s.Params) != 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("INTERFACE requires interface name")
	}
	return nil, fmt.Errorf("INTERFACE is only supported on Linux")
}

// tunPositional is shared with the Linux implementation for arity checks.
func tunPositional(s parse.Spec) (string, error) {
	n := 0
	for _, p := range s.Params {
		if p != "" {
			n++
		}
	}
	if n > 1 || len(s.Params) > 1 {
		return "", fmt.Errorf("too many parameters (%d instead of 0 or 1)", len(s.Params))
	}
	if len(s.Params) == 1 {
		return s.Params[0], nil
	}
	return "", nil
}
