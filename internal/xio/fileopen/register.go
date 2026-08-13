package fileopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("STDIO", openSTDIO)
	xio.Register("STDIN", openSTDIN)
	xio.Register("STDOUT", openSTDOUT)
	xio.Register("STDERR", openSTDERR)
	xio.Register("FD", openFD)
	xio.Register("PIPE", openPIPE)
	xio.Register("FIFO", openPIPE)
	xio.Register("ECHO", openPIPE)
	xio.Register("OPEN", openOPEN)
	xio.Register("FILE", openOPEN)
	xio.Register("CREATE", openCREATE)
	xio.Register("CREAT", openCREATE)
	xio.Register("GOPEN", openGOPEN)
	xio.Register("SOCKETPAIR", openSocketpair)
	xio.Register("PTY", openPTY)
	xio.Register("TEXT", openTEXT)
	xio.Register("STALL", openSTALL)
}
