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

const groupProcess = "Process"

func init() {
	execEnabled := func() bool { return FeatureEXEC }

	RegisterAddress(AddressDesc{Group: groupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC})
	RegisterAddress(AddressDesc{Group: groupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM})
	RegisterAddress(AddressDesc{Group: groupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL})
}
