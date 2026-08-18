//go:build unix && !linux

package main

import (
	"io"

	"golang.org/x/sys/unix"
)

func printLinuxSockopts(io.Writer, int) {}

func socketProtocol(int) (int, error) {
	return -1, unix.ENOPROTOOPT
}
