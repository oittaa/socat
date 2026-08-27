//go:build linux

package xio

import "golang.org/x/sys/unix"

type termiosBits = uint32

const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)

// Extra iflag/oflag/lflag bits from Linux glibc <termios.h>, advertised in
// classic tag-1.8.1.3 -hhh. Proved via tcsetattr/tcgetattr on a PTY.
const (
	termiosIUCLC   = termiosBits(unix.IUCLC)
	termiosOLCUC   = termiosBits(unix.OLCUC)
	termiosXCASE   = termiosBits(unix.XCASE)
	termiosOFILL   = termiosBits(unix.OFILL)
	termiosOFDEL   = termiosBits(unix.OFDEL)
	termiosECHOPRT = termiosBits(unix.ECHOPRT)
	termiosNLDLY   = termiosBits(unix.NLDLY)
	termiosCRDLY   = termiosBits(unix.CRDLY)
	termiosTABDLY  = termiosBits(unix.TABDLY)
	termiosBSDLY   = termiosBits(unix.BSDLY)
	termiosVTDLY   = termiosBits(unix.VTDLY)
	termiosFFDLY   = termiosBits(unix.FFDLY)
	termiosNL0     = termiosBits(unix.NL0)
	termiosCR0     = termiosBits(unix.CR0)
	termiosTAB0    = termiosBits(unix.TAB0)
	termiosBS0     = termiosBits(unix.BS0)
	termiosVT0     = termiosBits(unix.VT0)
	termiosFF0     = termiosBits(unix.FF0)
)

var platformTermiosFlags = []termiosFlag{
	{"iuclc", wordI, termiosIUCLC, 0},
	{"olcuc", wordO, termiosOLCUC, 0},
	{"xcase", wordL, termiosXCASE, 0},
	{"pendin", wordL, termiosBits(unix.PENDIN), 0},
	{"ofill", wordO, termiosOFILL, 0},
	{"ofdel", wordO, termiosOFDEL, 0},
	{"nl0", wordO, termiosNL0, termiosNLDLY},
	{"nl1", wordO, termiosBits(unix.NL1), termiosNLDLY},
	{"cr0", wordO, termiosCR0, termiosCRDLY},
	{"cr1", wordO, termiosBits(unix.CR1), termiosCRDLY},
	{"cr2", wordO, termiosBits(unix.CR2), termiosCRDLY},
	{"cr3", wordO, termiosBits(unix.CR3), termiosCRDLY},
	{"tab0", wordO, termiosTAB0, termiosTABDLY},
	{"tab1", wordO, termiosBits(unix.TAB1), termiosTABDLY},
	{"tab2", wordO, termiosBits(unix.TAB2), termiosTABDLY},
	{"tab3", wordO, termiosBits(unix.TAB3), termiosTABDLY},
	{"bs0", wordO, termiosBS0, termiosBSDLY},
	{"bs1", wordO, termiosBits(unix.BS1), termiosBSDLY},
	{"vt0", wordO, termiosVT0, termiosVTDLY},
	{"vt1", wordO, termiosBits(unix.VT1), termiosVTDLY},
	{"ff0", wordO, termiosFF0, termiosFFDLY},
	{"ff1", wordO, termiosBits(unix.FF1), termiosFFDLY},
}
