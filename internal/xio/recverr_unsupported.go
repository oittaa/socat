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

func DrainRecvErrFromConn(syscall.Conn, *Global) {}

func drainRecvErrFromConn(syscall.Conn, *Global) {}

func DrainRecvErrOnError(error, bool, syscall.Conn, *Global) {}
