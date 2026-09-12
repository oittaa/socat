package fileopen

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

// parseFDNum returns the FD / ACCEPT-FD number decoded at preparation.
func parseFDNum(s addrconfig.Address) (int, error) {
	if !s.File.FDSet {
		return -1, fmt.Errorf("%s: wrong number of parameters (%d instead of 1)", s.Type, len(s.Params))
	}
	return s.File.FD, nil
}

func openAcceptFD(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	fd, err := parseFDNum(s)
	if err != nil {
		return nil, err
	}
	// setsockopt-listen / ip-transparent apply before bind. ACCEPT-FD never
	// bind()s, so reject those options rather than ignore them.
	if err := xio.RejectGenericSetsockoptPhases(s, s.Type, xio.SockoptPhasePrebind); err != nil {
		return nil, err
	}
	if err := rejectAcceptFDTransparent(s); err != nil {
		return nil, err
	}
	return openAcceptFDNum(ctx, s, mode, g, fd)
}

func rejectAcceptFDTransparent(config addrconfig.Address) error {
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionTransparent {
			return fmt.Errorf("%s: option %q is not supported at this lifecycle phase", config.Type, "ip-transparent")
		}
	}
	return nil
}
