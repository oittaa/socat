//go:build windows

package netopen

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func rejectUnixTightSocklen(config addrconfig.Address) error {
	if config.Network.UnixTightSocklen.Set {
		return fmt.Errorf("unix-tightsocklen: not supported on this platform")
	}
	return nil
}

// unix-tightsocklen is rejected on Windows; bindUnixPath also rejects tight=false.
func listenUnixNetwork(ctx context.Context, s addrconfig.Address, network, path string) (net.Listener, error) {
	config := s
	if err := rejectUnixTightSocklen(config); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	var ln net.Listener
	err := xio.WithConfiguredUmask(config.File, func() error {
		var e error
		ln, e = xio.ListenStream(ctx, lc, network, path, s)
		return e
	})
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func dialUnixSocklen(req dialRequest, path, bindPath string) (net.Conn, error) {
	config := req.config
	if err := rejectUnixTightSocklen(config); err != nil {
		return nil, err
	}
	var conn net.Conn
	err := xio.WithRetry(req.ctx, req.g, req.config.Type, func() error {
		if err := prepareUnixClientBind(bindPath, config); err != nil {
			return err
		}
		// Bind in Control after socket() and snapshot that inode. Do not set
		// LocalAddr: Dialer would bind again, and a pre-dial Lstat cannot prove
		// this attempt created a path that appears during a failing connect.
		var created unixBindCreated
		d := net.Dialer{
			Timeout: req.timeout,
			Control: xio.DialControl(req.config, req.network, func(_ string, _ string, c syscall.RawConn) error {
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
		c, err := d.DialContext(req.ctx, req.network, path)
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
