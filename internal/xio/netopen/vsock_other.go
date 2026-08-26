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

func listenVSOCK(context.Context, uint32, parse.Spec, *xio.Global) (net.Listener, error) {
	return nil, fmt.Errorf("VSOCK is only implemented on Linux")
}

func dialVSOCK(context.Context, vsockEndpoint, parse.Spec, *xio.Global, time.Duration, func(string, string, syscall.RawConn) error) (net.Conn, error) {
	return nil, fmt.Errorf("VSOCK is only implemented on Linux")
}
