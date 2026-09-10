//go:build e2e && (linux || darwin)

package e2e_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
)

func listenAddrBusy(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES)
}

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
