//go:build darwin || windows

package xio

import (
	"fmt"
	"syscall"
)

func recvErrSupported() bool { return false }

func applyRecvErrValue(_ int, _ int) error {
	return fmt.Errorf("ip-recverr: not supported (no MSG_ERRQUEUE ReadMsg path)")
}

func DrainRecvErrOnError(error, bool, syscall.Conn, *Global) {}
