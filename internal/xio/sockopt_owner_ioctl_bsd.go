//go:build unix && !linux

package xio

// Darwin/BSD sys/filio.h: FIOSETOWN _IOW('f', 124, int) = 0x8004667c,
// FIOGETOWN _IOR('f', 123, int) = 0x4004667b. golang.org/x/sys/unix
// exports SIOCSPGRP / SIOCGPGRP but not FIOSETOWN / FIOGETOWN.
const (
	ownerIoctlFIOSETOWN = 0x8004667c
	ownerIoctlFIOGETOWN = 0x4004667b
)
