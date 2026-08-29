//go:build darwin

package xio

// Darwin/BSD sys/filio.h: FIOSETOWN _IOW('f', 124, int) = 0x8004667c,
// FIOGETOWN _IOR('f', 123, int) = 0x4004667b. golang.org/x/sys/unix
// exports SIOCSPGRP / SIOCGPGRP but not FIOSETOWN / FIOGETOWN.
//
// Darwin SET via FIOSETOWN writes so_pgid in the generic ioctl() switch
// (XNU bsd/kern/sys_generic.c). The matching FIOGETOWN case stores so_pgid
// into the kernel datap then breaks without copyout, so userspace GET
// stays 0; SIOCGPGRP / F_GETOWN copy out correctly. This port still
// applies classic FIOSETOWN; tests verify SET with those working getters.
const (
	ownerIoctlFIOSETOWN = 0x8004667c
	ownerIoctlFIOGETOWN = 0x4004667b
)
