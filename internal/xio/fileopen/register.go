package fileopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "STDIO",
		Syntax:     "STDIO",
		Desc:       "standard input and output (also -)",
		Opener:     openSTDIO,
		OptionCaps: xio.CapsFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "STDIN",
		Syntax:     "STDIN",
		Desc:       "standard input",
		Opener:     openSTDIN,
		OptionCaps: xio.CapsFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "STDOUT",
		Syntax:     "STDOUT",
		Desc:       "standard output",
		Opener:     openSTDOUT,
		OptionCaps: xio.CapsFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "STDERR",
		Syntax:     "STDERR",
		Desc:       "standard error",
		Opener:     openSTDERR,
		OptionCaps: xio.CapsFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "FD",
		Syntax:     "FD:<fdnum>",
		Desc:       "existing file descriptor",
		Opener:     openFD,
		OptionCaps: xio.CapsFD,
	})
	// ACCEPT is the public alias of ACCEPT-FD. Linux and macOS only;
	// FeatureACCEPTFD hides -h on Windows (like VSOCK).
	acceptFDEnabled := func() bool { return xio.FeatureACCEPTFD }
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "ACCEPT-FD",
		Syntax:     "ACCEPT-FD:<fdnum>",
		Desc:       "accept from a listening file descriptor",
		Enabled:    acceptFDEnabled,
		Opener:     openAcceptFD,
		OptionCaps: xio.CapsAcceptFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "ACCEPT",
		Syntax:     "ACCEPT:<fdnum>",
		Desc:       "same as ACCEPT-FD",
		Enabled:    acceptFDEnabled,
		Opener:     openAcceptFD,
		OptionCaps: xio.CapsAcceptFD,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "PIPE",
		Syntax:     "PIPE[:<filename>]",
		Desc:       "anonymous pipe or named FIFO",
		Opener:     openPIPE,
		OptionCaps: xio.CapsPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "FIFO",
		Syntax:     "FIFO[:<filename>]",
		Desc:       "same as PIPE",
		Opener:     openPIPE,
		OptionCaps: xio.CapsPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "ECHO",
		Syntax:     "ECHO",
		Desc:       "same as PIPE",
		Opener:     openPIPE,
		OptionCaps: xio.CapsPIPE,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "OPEN",
		Syntax:     "OPEN:<filename>",
		Desc:       "open a file",
		Opener:     openOPEN,
		OptionCaps: xio.CapsOpen,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "FILE",
		Syntax:     "FILE:<filename>",
		Desc:       "same as OPEN",
		Opener:     openOPEN,
		OptionCaps: xio.CapsOpen,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "CREATE",
		Syntax:     "CREATE:<filename>",
		Desc:       "create or truncate a file",
		Opener:     openCREATE,
		OptionCaps: xio.CapsCreate,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "CREAT",
		Syntax:     "CREAT:<filename>",
		Desc:       "same as CREATE",
		Opener:     openCREATE,
		OptionCaps: xio.CapsCreate,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "GOPEN",
		Syntax:     "GOPEN:<filename>",
		Desc:       "open or create a file (or socket)",
		Opener:     openGOPEN,
		OptionCaps: xio.CapsGOPEN,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "SOCKETPAIR",
		Syntax:     "SOCKETPAIR",
		Desc:       "unnamed UNIX socket pair",
		Enabled:    func() bool { return xio.FeatureSOCKETPAIR },
		Opener:     openSocketpair,
		OptionCaps: xio.CapsSocketSendto,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "TEXT",
		Syntax:     "TEXT:<string>",
		Desc:       "write a fixed string, then EOF",
		Opener:     openTEXT,
		OptionCaps: xio.CapsText,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "STALL",
		Syntax:     "STALL",
		Desc:       "block writes (full-pipe backpressure)",
		Enabled:    func() bool { return xio.FeatureSTALL },
		Opener:     openSTALL,
		OptionCaps: xio.CapsText,
	})
	xio.RegisterAddress(xio.AddressDesc{
		Group:      xio.GroupFiles,
		Name:       "PTY",
		Syntax:     "PTY",
		Desc:       "allocate a pseudo-terminal",
		Enabled:    func() bool { return xio.FeaturePTY },
		Opener:     openPTY,
		OptionCaps: xio.CapsPTY,
	})
}
