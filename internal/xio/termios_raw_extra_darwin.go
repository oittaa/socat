//go:build darwin

package xio

// Darwin headers lack these legacy termios flags; substitute zero.
const (
	rawExtraIflag termiosBits = 0
	rawExtraLflag termiosBits = 0
)
