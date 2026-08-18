//go:build windows

package xio

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openEXEC(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("EXEC is not supported on Windows")
}

func openSYSTEM(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("SYSTEM is not supported on Windows")
}

func openSHELL(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
	return nil, fmt.Errorf("SHELL is not supported on Windows")
}

func runExecNoFork(context.Context, relay.Stream, parse.Spec, *Global, Mode) error {
	return fmt.Errorf("EXEC is not supported on Windows")
}

func init() {
	Register("EXEC", openEXEC)
	Register("SYSTEM", openSYSTEM)
	Register("SHELL", openSHELL)
}
