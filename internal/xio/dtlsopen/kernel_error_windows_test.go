//go:build windows

package dtlsopen

import (
	"net"
	"syscall"
)

func kernelTooBig() error {
	return &net.OpError{Op: "write", Net: "udp", Err: syscall.Errno(10040)}
}
