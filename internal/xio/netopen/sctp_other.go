//go:build !linux

package netopen

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func listenSCTP(context.Context, string, string, string, parse.Spec) (net.Listener, error) {
	return nil, fmt.Errorf("SCTP is only implemented on Linux")
}

func dialSCTPAll(context.Context, string, string, string, parse.Spec, *xio.Global, time.Duration, func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	return nil, fmt.Errorf("SCTP is only implemented on Linux")
}
