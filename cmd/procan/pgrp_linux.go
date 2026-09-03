//go:build linux

package main

import "golang.org/x/sys/unix"

func foregroundProcessGroup(fd int) (int, error) {
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPGRP)
	return int(int32(n)), err // #nosec G115 -- kernel returns a signed 32-bit pid_t
}
