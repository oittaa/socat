//go:build windows

package netopen

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func listenUnixNetwork(ctx context.Context, s parse.Spec, network, path string) (net.Listener, error) {
	if !unixTightSocklen(s) {
		return nil, fmt.Errorf("unix-tightsocklen=0: not supported on this platform")
	}
	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	var ln net.Listener
	err := xio.WithUmask(s, func() error {
		var e error
		ln, e = lc.Listen(ctx, network, path)
		return e
	})
	return ln, err
}

func dialUnixUntight(context.Context, parse.Spec, *xio.Global, string, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("unix-tightsocklen=0: not supported on this platform")
}

func bindUnixPath(fd int, name string, tight bool) error {
	if !tight {
		return fmt.Errorf("unix-tightsocklen=0: not supported on this platform")
	}
	return syscall.Bind(syscall.Handle(fd), &syscall.SockaddrUnix{Name: name})
}
