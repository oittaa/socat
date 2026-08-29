//go:build linux && (mips || mipsle || mips64 || mips64le)

package xio

// Architecture-specific MIPS Linux ioctl numbers
// (arch/mips/include/uapi/asm/sockios.h), not asm-generic 0x8901.
// FIOSETOWN _IOW('f', 124, int) = 0x8004667c,
// FIOGETOWN _IOR('f', 123, int) = 0x4004667b.
// SIOCSPGRP is unix.SIOCSPGRP (0x80047308) on these GOARCH values.
const (
	ownerIoctlFIOSETOWN = 0x8004667c
	ownerIoctlFIOGETOWN = 0x4004667b
)
