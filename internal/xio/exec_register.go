package xio

import "github.com/oittaa/socat/internal/addrconfig"

func init() {
	execEnabled := func() bool { return FeatureEXEC }
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC, OptionCaps: CapsExec, Kind: addrconfig.AddressKindEXEC})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM, OptionCaps: CapsExec, Kind: addrconfig.AddressKindSYSTEM})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL, OptionCaps: CapsSHELL, Kind: addrconfig.AddressKindSHELL})
}
