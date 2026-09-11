//go:build darwin || windows

package tunopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"

	"github.com/oittaa/socat/internal/xio"
)

func openTUN(_ context.Context, _ addrconfig.Address, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("TUN is only supported on Linux")
}

func openINTERFACE(_ context.Context, s addrconfig.Address, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if len(s.Params) != 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("INTERFACE requires interface name")
	}
	return nil, fmt.Errorf("INTERFACE is only supported on Linux")
}
