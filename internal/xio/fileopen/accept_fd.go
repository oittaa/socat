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
	// Classic xioopen_accept_fd uses strtoul(..., 0) (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is the same xio-fdnum.c).
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
	// setsockopt-listen / ip-transparent are classic PH_PREBIND. ACCEPT-FD
	// never bind()s; applyopts after accept is PH_FD / PH_PASTSOCKET /
	// PH_CONNECTED only. Reject rather than ignore (no silent no-op).
	if err := xio.RejectGenericSetsockoptPhases(s, s.Type, xio.SockoptPhasePrebind); err != nil {
		return nil, err
	}
	if s.HasOption("ip-transparent") {
		return nil, fmt.Errorf("%s: option %q is not supported at this lifecycle phase", s.Type, "ip-transparent")
	}
	return openAcceptFDNum(ctx, s, mode, g, fd)
}
