//go:build windows

package xio

import "golang.org/x/sys/windows"

func getUDPSocketBuffers(fd int) (rcv, snd int, err error) {
	h := windows.Handle(fd)
	rcv, err = windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}
	snd, err = windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_SNDBUF)
	if err != nil {
		return 0, 0, err
	}
	return rcv, snd, nil
}
