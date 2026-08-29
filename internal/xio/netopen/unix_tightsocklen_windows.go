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

// unix-tightsocklen is rejected on Windows; bindUnixPath also rejects tight=false.
func listenUnixNetwork(ctx context.Context, s parse.Spec, network, path string) (net.Listener, error) {
	if s.HasOption("unix-tightsocklen") {
		return nil, fmt.Errorf("unix-tightsocklen: not supported on this platform")
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

func dialUnixSocklen(ctx context.Context, s parse.Spec, g *xio.Global, network, path, bindPath string) (net.Conn, error) {
	if s.HasOption("unix-tightsocklen") {
		return nil, fmt.Errorf("unix-tightsocklen: not supported on this platform")
	}
	var conn net.Conn
	err := xio.WithRetry(ctx, s, g, s.Type, func() error {
		d := net.Dialer{
			Timeout: xio.ConnectTimeout(s),
			Control: xio.DialControl(s, network, nil),
		}
		if bindPath != "" {
			cleanupUnixBind(bindPath)
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: network}
		}
		c, err := d.DialContext(ctx, network, path)
		if err != nil {
			cleanupUnixBind(bindPath)
			return err
		}
		conn = c
		return nil
	})
	return conn, err
}

func bindUnixPath(fd int, name string, tight bool) error {
	if !tight {
		return fmt.Errorf("unix-tightsocklen=0: not supported on this platform")
	}
	return syscall.Bind(syscall.Handle(fd), &syscall.SockaddrUnix{Name: name})
}
