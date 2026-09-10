//go:build e2e && windows

package e2e_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock SO_EXCLUSIVEADDRUSE is (~SO_REUSEADDR); x/sys/windows does not export it.
const soExclusiveAddrUse = ^0x4

func listenAddrBusy(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}

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

func portOccupied(ctx context.Context, network, addr string) (bool, error) {
	lc := exclusiveListenConfig()
	if strings.HasPrefix(network, "udp") {
		pc, err := lc.ListenPacket(ctx, network, addr)
		if err != nil {
			return true, nil
		}
		_ = pc.Close()
		return false, nil
	}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return true, nil
	}
	_ = ln.Close()
	return false, nil
}
