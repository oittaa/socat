//go:build e2e && windows

package e2e_test

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock SO_EXCLUSIVEADDRUSE is (~SO_REUSEADDR); x/sys/windows does not export it.
const soExclusiveAddrUse = ^0x4

func exclusiveListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				h := windows.Handle(fd)
				_ = windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_REUSEADDR, 0)
				opErr = windows.SetsockoptInt(h, windows.SOL_SOCKET, soExclusiveAddrUse, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
}
