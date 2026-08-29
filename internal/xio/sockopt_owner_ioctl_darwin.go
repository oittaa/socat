//go:build darwin

package xio

// Darwin FIOSETOWN (0x8004667c) and FIOGETOWN (0x4004667b).
// x/sys/unix does not export these. FIOGETOWN does not copy so_pgid out;
// tests verify SET via SIOCGPGRP / F_GETOWN.
const (
	ownerIoctlFIOSETOWN = 0x8004667c
	ownerIoctlFIOGETOWN = 0x4004667b
)
