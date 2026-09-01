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
		ln, e = xio.ListenStream(ctx, lc, network, path, s)
		return e
	})
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func dialUnixSocklen(ctx context.Context, s parse.Spec, g *xio.Global, network, path, bindPath string) (net.Conn, error) {
	if s.HasOption("unix-tightsocklen") {
		return nil, fmt.Errorf("unix-tightsocklen: not supported on this platform")
	}
	var conn net.Conn
	err := xio.WithRetry(ctx, s, g, s.Type, func() error {
		if err := prepareUnixClientBind(bindPath, s); err != nil {
			return err
		}
		// Bind in Control after socket() and snapshot that inode. Do not set
		// LocalAddr: Dialer would bind again, and a pre-dial Lstat cannot prove
		// this attempt created a path that appears during a failing connect.
		var created unixBindCreated
		d := net.Dialer{
			Timeout: xio.ConnectTimeout(s),
			Control: xio.DialControl(s, network, func(_ string, _ string, c syscall.RawConn) error {
				if bindPath == "" {
					return nil
				}
				var bindErr error
				if err := c.Control(func(fd uintptr) {
					bindErr = bindUnixPath(int(fd), bindPath, true)
				}); err != nil {
					return err
				}
				if bindErr != nil {
					return bindErr
				}
				created = rememberUnixBindCreated(bindPath)
				return nil
			}),
		}
		c, err := d.DialContext(ctx, network, path)
		if err != nil {
			created.unlink()
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
