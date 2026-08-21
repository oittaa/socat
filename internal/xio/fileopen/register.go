package fileopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "STDIO",
		Syntax: "STDIO",
		Desc:   "standard input and output (also -)",
		Opener: openSTDIO,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "STDIN",
		Syntax: "STDIN",
		Desc:   "standard input",
		Opener: openSTDIN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "STDOUT",
		Syntax: "STDOUT",
		Desc:   "standard output",
		Opener: openSTDOUT,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "STDERR",
		Syntax: "STDERR",
		Desc:   "standard error",
		Opener: openSTDERR,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "FD",
		Syntax: "FD:<fdnum>",
		Desc:   "existing file descriptor",
		Opener: openFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "PIPE",
		Syntax: "PIPE[:<filename>]",
		Desc:   "anonymous pipe or named FIFO",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "FIFO",
		Syntax: "FIFO[:<filename>]",
		Desc:   "same as PIPE",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "ECHO",
		Syntax: "ECHO",
		Desc:   "same as PIPE",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "OPEN",
		Syntax: "OPEN:<filename>",
		Desc:   "open a file",
		Opener: openOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "FILE",
		Syntax: "FILE:<filename>",
		Desc:   "same as OPEN",
		Opener: openOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "CREATE",
		Syntax: "CREATE:<filename>",
		Desc:   "create or truncate a file",
		Opener: openCREATE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "CREAT",
		Syntax: "CREAT:<filename>",
		Desc:   "same as CREATE",
		Opener: openCREATE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "GOPEN",
		Syntax: "GOPEN:<filename>",
		Desc:   "open or create a file (or socket)",
		Opener: openGOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   xio.GroupFiles,
		Name:    "SOCKETPAIR",
		Syntax:  "SOCKETPAIR",
		Desc:    "unnamed UNIX socket pair",
		Enabled: func() bool { return xio.FeatureSOCKETPAIR },
		Opener:  openSocketpair,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  xio.GroupFiles,
		Name:   "TEXT",
		Syntax: "TEXT:<string>",
		Desc:   "write a fixed string, then EOF",
		Opener: openTEXT,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   xio.GroupFiles,
		Name:    "STALL",
		Syntax:  "STALL",
		Desc:    "block writes (full-pipe backpressure)",
		Enabled: func() bool { return xio.FeatureSTALL },
		Opener:  openSTALL,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   xio.GroupFiles,
		Name:    "PTY",
		Syntax:  "PTY",
		Desc:    "allocate a pseudo-terminal",
		Enabled: func() bool { return xio.FeaturePTY },
		Opener:  openPTY,
	})
}
