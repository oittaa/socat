//go:build darwin

package main

import "golang.org/x/sys/unix"

func foregroundProcessGroup(fd int) (int, error) {
	if _, err := unix.IoctlGetTermios(fd, unix.TIOCGETA); err != nil {
		return 0, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	return int(int32(n)), err // #nosec G115 -- kernel returns a signed 32-bit pid_t
}
