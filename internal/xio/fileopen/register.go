package fileopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	const files = xio.GroupFiles
	fd := addrconfig.AddressKindFD
	file := addrconfig.AddressKindFile
	create := addrconfig.AddressKindCREATE
	pipe := addrconfig.AddressKindPIPE
	gopen := addrconfig.AddressKindGOPEN
	// ACCEPT is the public alias of ACCEPT-FD. Linux and macOS only;
	// FeatureACCEPTFD hides -h on Windows (like VSOCK).
	acceptFDEnabled := func() bool { return xio.FeatureACCEPTFD }
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "STDIO", Syntax: "STDIO", Desc: "standard input and output (also -)", Opener: openSTDIO, OptionCaps: xio.CapsFD, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "STDIN", Syntax: "STDIN", Desc: "standard input", Opener: openSTDIN, OptionCaps: xio.CapsFD, Directions: xio.ModeRead, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "STDOUT", Syntax: "STDOUT", Desc: "standard output", Opener: openSTDOUT, OptionCaps: xio.CapsFD, Directions: xio.ModeWrite, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "STDERR", Syntax: "STDERR", Desc: "standard error", Opener: openSTDERR, OptionCaps: xio.CapsFD, Directions: xio.ModeWrite, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "FD", Syntax: "FD:<fdnum>", Desc: "existing file descriptor", Opener: openFD, OptionCaps: xio.CapsFD, Kind: fd, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "ACCEPT-FD", Syntax: "ACCEPT-FD:<fdnum>", Desc: "accept from a listening file descriptor", Enabled: acceptFDEnabled, Opener: openAcceptFD, OptionCaps: xio.CapsAcceptFD, Kind: fd, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "ACCEPT", Syntax: "ACCEPT:<fdnum>", Desc: "same as ACCEPT-FD", Enabled: acceptFDEnabled, Opener: openAcceptFD, OptionCaps: xio.CapsAcceptFD, Kind: fd, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "PIPE", Syntax: "PIPE[:<filename>]", Desc: "anonymous pipe or named FIFO", Opener: openPIPE, OptionCaps: xio.CapsPIPE, Kind: pipe, Params: xio.Params(0, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "FIFO", Syntax: "FIFO[:<filename>]", Desc: "same as PIPE", Opener: openPIPE, OptionCaps: xio.CapsPIPE, Kind: pipe, Params: xio.Params(0, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "ECHO", Syntax: "ECHO[:<filename>]", Desc: "same as PIPE", Opener: openPIPE, OptionCaps: xio.CapsPIPE, Kind: pipe, Params: xio.Params(0, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "OPEN", Syntax: "OPEN:<filename>", Desc: "open a file", Opener: openOPEN, OptionCaps: xio.CapsOpen, Kind: file, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "FILE", Syntax: "FILE:<filename>", Desc: "same as OPEN", Opener: openOPEN, OptionCaps: xio.CapsOpen, Kind: file, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "CREATE", Syntax: "CREATE:<filename>", Desc: "create or truncate a file", Opener: openCREATE, OptionCaps: xio.CapsCreate, Directions: xio.ModeWrite, Kind: create, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "CREAT", Syntax: "CREAT:<filename>", Desc: "same as CREATE", Opener: openCREATE, OptionCaps: xio.CapsCreate, Directions: xio.ModeWrite, Kind: create, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "GOPEN", Syntax: "GOPEN:<filename>", Desc: "open or create a file (or socket)", Opener: openGOPEN, OptionCaps: xio.CapsGOPEN, Kind: gopen, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "SOCKETPAIR", Syntax: "SOCKETPAIR", Desc: "unnamed UNIX socket pair", Enabled: func() bool { return xio.FeatureSOCKETPAIR }, Opener: openSocketpair, OptionCaps: xio.CapsSocketSendto, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "TEXT", Syntax: "TEXT:<string>", Desc: "write a fixed string, then EOF", Opener: openTEXT, OptionCaps: xio.CapsText, Params: xio.Params(1, 1)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "STALL", Syntax: "STALL", Desc: "block writes (full-pipe backpressure)", Enabled: func() bool { return xio.FeatureSTALL }, Opener: openSTALL, OptionCaps: xio.CapsText, Params: xio.Params(0, 0)})
	xio.RegisterAddress(xio.AddressDesc{Group: files, Name: "PTY", Syntax: "PTY", Desc: "allocate a pseudo-terminal", Enabled: func() bool { return xio.FeaturePTY }, Opener: openPTY, OptionCaps: xio.CapsPTY, Params: xio.Params(0, 0)})
}
