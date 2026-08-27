//go:build unix && !linux && !darwin

package xio

import "golang.org/x/sys/unix"

type termiosBits = uint32

const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)

const (
	termiosIUCLC   termiosBits = 0
	termiosOLCUC   termiosBits = 0
	termiosXCASE   termiosBits = 0
	termiosOFILL   termiosBits = 0
	termiosOFDEL   termiosBits = 0
	termiosECHOPRT termiosBits = 0
	termiosNLDLY   termiosBits = 0
	termiosCRDLY   termiosBits = 0
	termiosTABDLY  termiosBits = 0
	termiosBSDLY   termiosBits = 0
	termiosVTDLY   termiosBits = 0
	termiosFFDLY   termiosBits = 0
	termiosNL0     termiosBits = 0
	termiosCR0     termiosBits = 0
	termiosTAB0    termiosBits = 0
	termiosBS0     termiosBits = 0
	termiosVT0     termiosBits = 0
	termiosFF0     termiosBits = 0
)

var platformTermiosFlags []termiosFlag
