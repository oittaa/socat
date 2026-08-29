//go:build linux && !mips && !mipsle && !mips64 && !mips64le

package xio

// FIOSETOWN / FIOGETOWN are not exported by golang.org/x/sys/unix.
// Linux asm-generic/sockios.h (amd64, arm64, and other non-MIPS GOARCH):
// FIOSETOWN=0x8901, SIOCSPGRP=0x8902, FIOGETOWN=0x8903, SIOCGPGRP=0x8904.
const (
	ownerIoctlFIOSETOWN = 0x8901
	ownerIoctlFIOGETOWN = 0x8903
)
