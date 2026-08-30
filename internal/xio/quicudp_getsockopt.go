//go:build linux || darwin

package xio

import "golang.org/x/sys/unix"

func getUDPSocketBuffers(fd int) (rcv, snd int) {
	rcv, _ = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	snd, _ = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	return rcv, snd
}
