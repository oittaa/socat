//go:build windows

package xio

import "golang.org/x/sys/windows"

func getUDPSocketBuffers(fd int) (rcv, snd int) {
	h := windows.Handle(fd)
	rcv, _ = windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVBUF)
	snd, _ = windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_SNDBUF)
	return rcv, snd
}
