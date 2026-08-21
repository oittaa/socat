package fileopen

import "github.com/oittaa/socat/internal/xio"

const groupFiles = "Files and stdio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "STDIO",
		Syntax: "STDIO",
		Desc:   "standard input and output (also -)",
		Opener: openSTDIO,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "STDIN",
		Syntax: "STDIN",
		Desc:   "standard input",
		Opener: openSTDIN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "STDOUT",
		Syntax: "STDOUT",
		Desc:   "standard output",
		Opener: openSTDOUT,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "STDERR",
		Syntax: "STDERR",
		Desc:   "standard error",
		Opener: openSTDERR,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "FD",
		Syntax: "FD:<fdnum>",
		Desc:   "existing file descriptor",
		Opener: openFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "PIPE",
		Syntax: "PIPE[:<filename>]",
		Desc:   "anonymous pipe or named FIFO",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "FIFO",
		Syntax: "FIFO[:<filename>]",
		Desc:   "same as PIPE",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "ECHO",
		Syntax: "ECHO",
		Desc:   "same as PIPE",
		Opener: openPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "OPEN",
		Syntax: "OPEN:<filename>",
		Desc:   "open a file",
		Opener: openOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "FILE",
		Syntax: "FILE:<filename>",
		Desc:   "same as OPEN",
		Opener: openOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "CREATE",
		Syntax: "CREATE:<filename>",
		Desc:   "create or truncate a file",
		Opener: openCREATE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "CREAT",
		Syntax: "CREAT:<filename>",
		Desc:   "same as CREATE",
		Opener: openCREATE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "GOPEN",
		Syntax: "GOPEN:<filename>",
		Desc:   "open or create a file (or socket)",
		Opener: openGOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   groupFiles,
		Name:    "SOCKETPAIR",
		Syntax:  "SOCKETPAIR",
		Desc:    "unnamed UNIX socket pair",
		Enabled: func() bool { return xio.FeatureSOCKETPAIR },
		Opener:  openSocketpair,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:  groupFiles,
		Name:   "TEXT",
		Syntax: "TEXT:<string>",
		Desc:   "write a fixed string, then EOF",
		Opener: openTEXT,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   groupFiles,
		Name:    "STALL",
		Syntax:  "STALL",
		Desc:    "block writes (full-pipe backpressure)",
		Enabled: func() bool { return xio.FeatureSTALL },
		Opener:  openSTALL,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:   groupFiles,
		Name:    "PTY",
		Syntax:  "PTY",
		Desc:    "allocate a pseudo-terminal",
		Enabled: func() bool { return xio.FeaturePTY },
		Opener:  openPTY,
	})
}
