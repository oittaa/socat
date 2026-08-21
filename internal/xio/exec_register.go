package xio

func init() {
	execEnabled := func() bool { return FeatureEXEC }
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "EXEC", Syntax: "EXEC:<command-line>", Desc: "run a program (argv)", Enabled: execEnabled, Opener: openEXEC})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SYSTEM", Syntax: "SYSTEM:<shell-command>", Desc: "run a shell command", Enabled: execEnabled, Opener: openSYSTEM})
	RegisterAddress(AddressDesc{Group: GroupProcess, Name: "SHELL", Syntax: "SHELL[:<shell-command>]", Desc: "interactive shell or command", Enabled: execEnabled, Opener: openSHELL})
}
