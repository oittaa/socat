package fileopen

import (
	"context"
	"fmt"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func parseAcceptFDNum(s parse.Spec) (int, error) {
	if len(s.Params) != 1 || s.Params[0] == "" {
		return -1, fmt.Errorf("%s: wrong number of parameters (%d instead of 1)", s.Type, len(s.Params))
	}
	// Base-0 ParseUint: 10, 0x10, and 010 are all valid FD numbers.
	n, err := strconv.ParseUint(s.Params[0], 0, 32)
	if err != nil {
		return -1, fmt.Errorf("error in FD number %q", s.Params[0])
	}
	return int(n), nil
}

func openAcceptFD(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	fd, err := parseAcceptFDNum(s)
	if err != nil {
		return nil, err
	}
	// setsockopt-listen / ip-transparent apply before bind. ACCEPT-FD never
	// bind()s; after accept only after open / after socket() / after
	// connect/accept run. Reject rather than ignore.
	if err := xio.RejectGenericSetsockoptPhases(s, s.Type, xio.SockoptPhasePrebind); err != nil {
		return nil, err
	}
	if s.HasOption("ip-transparent") {
		return nil, fmt.Errorf("%s: option %q is not supported at this lifecycle phase", s.Type, "ip-transparent")
	}
	return openAcceptFDNum(ctx, s, mode, g, fd)
}
