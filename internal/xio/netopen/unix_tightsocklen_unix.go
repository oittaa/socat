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
	if tight {
		return unix.Bind(fd, &unix.SockaddrUnix{Name: name})
	}
	return unixBindUntight(fd, name)
}

func unixBindUntight(fd int, name string) error {
	sa, err := fillRawSockaddrUnix(name)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(unix.SizeofSockaddrUnix)) // #nosec G103 -- bind(2) length is sizeof(sockaddr_un); x/sys Bind always uses a tight socklen
	if errno != 0 {
		return errno
	}
	return nil
}

func unixConnectUntight(fd int, name string) error {
	sa, err := fillRawSockaddrUnix(name)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(unix.SizeofSockaddrUnix)) // #nosec G103 -- connect(2) length is sizeof(sockaddr_un); x/sys Connect always uses a tight socklen
	if errno != 0 {
		return errno
	}
	return nil
}

func fillRawSockaddrUnix(name string) (unix.RawSockaddrUnix, error) {
	var sa unix.RawSockaddrUnix
	sa.Family = unix.AF_UNIX
	if name != "" && name[0] == '@' {
		name = string([]byte{0}) + name[1:]
	}
	if len(name) > len(sa.Path) {
		return sa, fmt.Errorf("unix socket path too long")
	}
	for i := 0; i < len(name); i++ {
		sa.Path[i] = int8(name[i]) // #nosec G115 -- sockaddr_un.sun_path is a C char[]; pathname bytes are stored as-is
	}
	return sa, nil
}

func listenUnixNetwork(ctx context.Context, s parse.Spec, network, path string) (net.Listener, error) {
	if unixTightSocklen(s) {
		lc := net.ListenConfig{Control: xio.ListenControl(s)}
		var ln net.Listener
		err := xio.WithUmask(s, func() error {
			var e error
			ln, e = lc.Listen(ctx, network, path)
			return e
		})
		return ln, err
	}
	return listenUnixUntight(s, network, path)
}

func listenUnixUntight(s parse.Spec, network, path string) (net.Listener, error) {
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
	err = xio.WithUmask(s, func() error {
		return unixBindUntight(fd, path)
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

func dialUnixUntight(ctx context.Context, s parse.Spec, g *xio.Global, network, path, bindPath string) (net.Conn, error) {
	typ, err := unixNetworkSocktype(network)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	err = xio.WithRetry(ctx, s, g, s.Type, func() error {
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
		if bindPath != "" {
			if err := unixBindUntight(fd, bindPath); err != nil {
				logx.CloseErr(unix.Close(fd))
				cleanupUnixBind(bindPath)
				return err
			}
		}
		if err := unixConnectUntight(fd, path); err != nil {
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
