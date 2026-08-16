//go:build darwin

package xio

import "golang.org/x/sys/unix"

type termiosBits = uint64

const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)
