//go:build linux

package main

import (
	"io"

	"golang.org/x/sys/unix"
)

func printLinuxSockopts(out io.Writer, fd int) {
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_NO_CHECK, "NO_CHECK")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_PRIORITY, "PRIORITY")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, "TCP_KEEPIDLE")
}

func socketProtocol(fd int) (int, error) {
	return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
}
