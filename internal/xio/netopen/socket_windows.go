//go:build windows

package netopen

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openSocketConnect(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-CONNECT is not supported on Windows")
}

func openSocketListen(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-LISTEN is not supported on Windows")
}

func openSocketSendto(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-SENDTO is not supported on Windows")
}

func openSocketDatagram(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-DATAGRAM is not supported on Windows")
}

func openSocketRecv(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-RECV is not supported on Windows")
}

func openSocketRecvfrom(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error) {
	return nil, fmt.Errorf("SOCKET-RECVFROM is not supported on Windows")
}
