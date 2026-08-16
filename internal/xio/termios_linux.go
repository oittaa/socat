//go:build linux

package xio

import "golang.org/x/sys/unix"

type termiosBits = uint32

const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)
