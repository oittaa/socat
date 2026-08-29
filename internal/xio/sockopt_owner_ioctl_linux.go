//go:build linux

package xio

// FIOSETOWN / FIOGETOWN are not exported by golang.org/x/sys/unix.
// Linux asm-generic/sockios.h (most CI GOARCH, including amd64/arm64):
// FIOSETOWN=0x8901, SIOCSPGRP=0x8902, FIOGETOWN=0x8903, SIOCGPGRP=0x8904.
// MIPS Linux uses BSD-style filio numbers; this port's Linux CI is
// asm-generic.
const (
	ownerIoctlFIOSETOWN = 0x8901
	ownerIoctlFIOGETOWN = 0x8903
)
