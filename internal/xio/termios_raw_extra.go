//go:build unix && (linux || aix || openbsd || solaris)

package xio

import "golang.org/x/sys/unix"

// Classic defines missing legacy termios flags to zero. These platforms
// expose IUCLC and XCASE through x/sys/unix, so retain their real masks.
const (
	rawExtraIflag = termiosBits(unix.IUCLC)
	rawExtraLflag = termiosBits(unix.XCASE)
)
