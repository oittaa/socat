//go:build unix && !linux && !darwin

package xio

import "golang.org/x/sys/unix"

type termiosBits = uint32

const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)
