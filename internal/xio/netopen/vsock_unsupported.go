//go:build darwin || windows

package netopen

import (
	"context"
	"fmt"
	"net"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func listenVSOCK(context.Context, uint32, parse.Spec, *xio.Global) (net.Listener, error) {
	return nil, fmt.Errorf("VSOCK is only implemented on Linux")
}

func dialVSOCK(dialRequest, vsockEndpoint) (net.Conn, error) {
	return nil, fmt.Errorf("VSOCK is only implemented on Linux")
}
