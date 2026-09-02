//go:build darwin

package filan

import (
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func printLinuxSockopts(*outbuf.Buf, int) {}

// SocketProtocol returns SO_PROTOCOL for fd.
func SocketProtocol(int) (int, error) {
	return -1, unix.ENOPROTOOPT
}
