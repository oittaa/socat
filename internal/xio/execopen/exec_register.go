package execopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	xio.RegisterExecNoFork(runExecNoFork)
	execEnabled := func() bool { return xio.FeatureEXEC }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC, OptionCaps: xio.CapsExec, Kind: addrconfig.AddressKindEXEC, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM, OptionCaps: xio.CapsExec, Kind: addrconfig.AddressKindSYSTEM, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL, OptionCaps: xio.CapsSHELL, Kind: addrconfig.AddressKindSHELL, Params: xio.Params(0, 1)})
}
