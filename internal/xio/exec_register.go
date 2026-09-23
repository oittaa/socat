package xio

import "github.com/oittaa/socat/internal/addrconfig"

func init() {
	execEnabled := func() bool { return FeatureEXEC }
	RegisterAddress(AddressDesc{Group: groupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC, OptionCaps: capsExec, Kind: addrconfig.AddressKindEXEC, Params: Params(1, 1)})
	RegisterAddress(AddressDesc{Group: groupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM, OptionCaps: capsExec, Kind: addrconfig.AddressKindSYSTEM, Params: Params(1, 1)})
	RegisterAddress(AddressDesc{Group: groupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL, OptionCaps: capsSHELL, Kind: addrconfig.AddressKindSHELL, Params: Params(0, 1)})
}
