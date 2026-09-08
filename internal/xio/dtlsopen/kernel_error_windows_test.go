//go:build windows

package dtlsopen

import (
	"net"
	"syscall"
)

func kernelTooBig() *net.OpError {
	return &net.OpError{Op: "write", Net: "udp", Err: syscall.Errno(10040)}
}
