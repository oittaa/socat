//go:build linux || darwin

package dtlsopen

import (
	"net"
	"syscall"
)

func kernelTooBig() *net.OpError {
	return &net.OpError{Op: "write", Net: "udp", Err: syscall.EMSGSIZE}
}
