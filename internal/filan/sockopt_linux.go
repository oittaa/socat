//go:build linux

package filan

import (
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func printLinuxSockopts(b *outbuf.Buf, fd int) {
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_NO_CHECK, "NO_CHECK")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_PRIORITY, "PRIORITY")
	printSockoptInt(b, fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, "TCP_KEEPIDLE")
}

// SocketProtocol returns SO_PROTOCOL for fd.
func SocketProtocol(fd int) (int, error) {
	return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
}
