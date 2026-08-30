//go:build linux || darwin

package xio

import "golang.org/x/sys/unix"

func getUDPSocketBuffers(fd int) (rcv, snd int, err error) {
	rcv, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}
	snd, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		return 0, 0, err
	}
	return rcv, snd, nil
}
