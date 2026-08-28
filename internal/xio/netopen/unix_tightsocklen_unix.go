//go:build unix

package netopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func bindUnixPath(fd int, name string, tight bool) error {
	return unixBindPath(fd, name, tight)
}

func unixBindPath(fd int, name string, tight bool) error {
	sa, n, err := unixRawSockaddr(name, tight)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- bind(2) length is xiosetunix's socklen_t
	if errno != 0 {
		return errno
	}
	return nil
}

func unixConnectPath(ctx context.Context, fd int, name string, tight bool) error {
	sa, n, err := unixRawSockaddr(name, tight)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- connect(2) length is xiosetunix's socklen_t
		if errno != 0 {
			done <- errno
			return
		}
		done <- nil
	}()
	select {
	case <-ctx.Done():
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		<-done
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func unixRawSockaddr(name string, tight bool) (unix.RawSockaddrUnix, int, error) {
	var sa unix.RawSockaddrUnix
	sa.Family = unix.AF_UNIX
	abstract := name != "" && (name[0] == '@' || name[0] == 0)
	path := name
	if name != "" && name[0] == '@' {
		path = string([]byte{0}) + name[1:]
	}
	if len(path) > len(sa.Path) {
		return sa, 0, fmt.Errorf("unix socket path too long")
	}
	for i := 0; i < len(path); i++ {
		sa.Path[i] = int8(path[i]) // #nosec G115 -- sockaddr_un.sun_path is a C char[]; pathname bytes are stored as-is
	}
	pathlen := len(path)
	if abstract {
		if pathlen > 0 {
			pathlen--
		}
	}
	n := classicUnixSockaddrLen(pathlen, len(sa.Path), unix.SizeofSockaddrUnix, abstract, tight)
	if tight {
		setUnixSockaddrLen(&sa, n)
	}
	return sa, n, nil
}

func listenUnixNetwork(ctx context.Context, s parse.Spec, network, path string) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	typ, err := unixNetworkSocktype(network)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, typ|sockCloexec, 0)
	if err != nil {
		return nil, err
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(fd)
	}
	if err := xio.ApplyPastSocketThenPrebind(fd, s, network); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	tight := unixTightSocklen(s)
	err = xio.WithUmask(s, func() error {
		return unixBindPath(fd, path, tight)
	})
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	nfd, err := dupFD(fd)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), path)
	ln, err := net.FileListener(f)
	logx.CloseQuiet(f)
	logx.CloseErr(unix.Close(fd))
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func unixNetworkSocktype(network string) (int, error) {
	switch network {
	case "unix":
		return unix.SOCK_STREAM, nil
	case "unixpacket":
		return unix.SOCK_SEQPACKET, nil
	case "unixgram":
		return unix.SOCK_DGRAM, nil
	default:
		return 0, fmt.Errorf("unsupported unix network %q", network)
	}
}

func dialUnixSocklen(ctx context.Context, s parse.Spec, g *xio.Global, network, path, bindPath string) (net.Conn, error) {
	typ, err := unixNetworkSocktype(network)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	err = xio.WithRetry(ctx, s, g, s.Type, func() error {
		cctx := ctx
		var cancel context.CancelFunc
		if timeout := xio.ConnectTimeout(s); timeout > 0 {
			cctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		if bindPath != "" {
			cleanupUnixBind(bindPath)
		}
		fd, err := unix.Socket(unix.AF_UNIX, typ|sockCloexec, 0)
		if err != nil {
			return err
		}
		if sockCloexec == 0 {
			unix.CloseOnExec(fd)
		}
		if err := xio.ApplyPastSocketThenPrebind(fd, s, network); err != nil {
			logx.CloseErr(unix.Close(fd))
			return err
		}
		tight := unixTightSocklen(s)
		if bindPath != "" {
			if err := unixBindPath(fd, bindPath, tight); err != nil {
				logx.CloseErr(unix.Close(fd))
				cleanupUnixBind(bindPath)
				return err
			}
		}
		if err := unixConnectPath(cctx, fd, path, tight); err != nil {
			logx.CloseErr(unix.Close(fd))
			cleanupUnixBind(bindPath)
			return err
		}
		nfd, err := dupFD(fd)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return err
		}
		f := os.NewFile(uintptr(nfd), path)
		c, err := net.FileConn(f)
		logx.CloseQuiet(f)
		logx.CloseErr(unix.Close(fd))
		if err != nil {
			cleanupUnixBind(bindPath)
			return err
		}
		conn = c
		return nil
	})
	return conn, err
}
