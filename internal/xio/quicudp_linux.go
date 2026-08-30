//go:build linux

package xio

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func forceQUICUDPBuffers(pc net.PacketConn, bytes int) {
	if pc == nil || bytes <= 0 {
		return
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bytes)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bytes)
	})
}
