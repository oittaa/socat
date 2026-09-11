//go:build windows

package xio

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

func openEXEC(context.Context, addrconfig.Address, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("EXEC is not supported on Windows")
}

func openSYSTEM(context.Context, addrconfig.Address, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("SYSTEM is not supported on Windows")
}

func openSHELL(context.Context, addrconfig.Address, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("SHELL is not supported on Windows")
}

func runExecNoFork(context.Context, relay.Stream, addrconfig.Address, *Global, Mode) error {
	return fmt.Errorf("EXEC is not supported on Windows")
}
