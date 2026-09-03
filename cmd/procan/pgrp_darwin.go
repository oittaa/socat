//go:build darwin

package main

import "golang.org/x/sys/unix"

func foregroundProcessGroup(fd int) (int, error) {
	return unix.IoctlGetInt(fd, unix.TIOCGPGRP)
}
