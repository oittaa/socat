//go:build windows

package execopen

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func openEXEC(context.Context, addrconfig.Address, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("EXEC is not supported on Windows")
}

func openSYSTEM(context.Context, addrconfig.Address, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SYSTEM is not supported on Windows")
}

func openSHELL(context.Context, addrconfig.Address, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SHELL is not supported on Windows")
}

func runExecNoFork(context.Context, relay.Stream, addrconfig.Address, *xio.Global, xio.Mode) error {
	return fmt.Errorf("EXEC is not supported on Windows")
}
