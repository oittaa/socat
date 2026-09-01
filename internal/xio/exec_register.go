package xio

import "github.com/oittaa/socat/internal/parse"

func execUsesPTY(s parse.Spec) bool {
	return s.BoolOption("pty") || s.BoolOption("ptmx") || s.BoolOption("openpty")
}

func init() {
	execEnabled := func() bool { return FeatureEXEC }
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC, OptionCaps: CapsExec})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM, OptionCaps: CapsExec})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL, OptionCaps: CapsSHELL})
}
