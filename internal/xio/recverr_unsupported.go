//go:build darwin || windows

package xio

import (
	"fmt"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
)

func recvErrSupported() bool { return false }

func applyRecvErrSockopt(_ int, o parse.Option) error {
	name, ok := recvErrOptionName(o)
	if !ok {
		name = "ip-recverr"
	}
	return fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", name)
}

func DrainRecvErrFromConn(syscall.Conn, *Global) {}

func drainRecvErrFromConn(syscall.Conn, *Global) {}
