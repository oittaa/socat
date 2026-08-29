//go:build darwin

package xio

// Classic substitutes zero when the platform headers lack these legacy
// termios flags. x/sys/unix likewise does not expose them on these systems.
const (
	rawExtraIflag termiosBits = 0
	rawExtraLflag termiosBits = 0
)
