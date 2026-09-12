//go:build e2e && (linux || darwin)

package e2e_test

import (
	"errors"
	"net"
	"syscall"
)

func exclusiveListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 0)
			})
			return errors.Join(err, opErr)
		},
	}
}
