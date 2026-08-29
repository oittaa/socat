//go:build linux

package xio

import "golang.org/x/sys/unix"

// Linux exposes IUCLC and XCASE through x/sys/unix; retain their real masks.
const (
	rawExtraIflag = termiosBits(unix.IUCLC)
	rawExtraLflag = termiosBits(unix.XCASE)
)
