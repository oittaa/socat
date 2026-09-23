//go:build darwin || windows

package xio

import (
	"syscall"
)

func DrainRecvErrOnError(error, bool, syscall.Conn, *Global) {}
