//go:build darwin || windows

package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func listenSCTP(context.Context, string, string, addrconfig.PortTarget, addrconfig.Address) (net.Listener, error) {
	return nil, fmt.Errorf("SCTP is only implemented on Linux")
}

func dialSCTPAll(context.Context, xio.DialTarget, addrconfig.Address, *xio.Global, time.Duration, func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	return nil, fmt.Errorf("SCTP is only implemented on Linux")
}
