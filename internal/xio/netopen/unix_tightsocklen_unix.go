//go:build linux || darwin

package netopen

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"time"
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
	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- bind(2) length is classicUnixSockaddrLen
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
	// Always set O_NONBLOCK so a canceled context can abort without relying
	// on shutdown(2), which does not interrupt an unconnected blocking socket.
	// Wait for POLLOUT|POLLERR after EINPROGRESS.
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- connect(2) length is classicUnixSockaddrLen
	for {
		if errno == 0 {
			return nil
		}
		if errno == unix.EINPROGRESS {
			return waitUnixConnect(ctx, fd)
		}
		if errno != unix.EAGAIN && errno != unix.EWOULDBLOCK {
			return errno
		}
		// AF_UNIX returns EAGAIN when the listen queue is full: connect(2) was
		// not started, so POLLOUT/SO_ERROR would be a false completion. Retry
		// until the context deadline (connect-timeout) or cancel.
		if err := waitUnixConnectRetry(ctx); err != nil {
			return err
		}
		_, _, errno = unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- connect(2) length is classicUnixSockaddrLen
	}
}

func waitUnixConnectRetry(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := time.Duration(unixConnectCancelPollMs) * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		rem := time.Until(deadline)
		if rem <= 0 {
			return deadlineExceeded(ctx)
		}
		if rem < timeout {
			timeout = rem
		}
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

const unixConnectCancelPollMs = 25

func waitUnixConnect(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := unixConnectCancelPollMs
		if deadline, ok := ctx.Deadline(); ok {
			rem := time.Until(deadline)
			if rem <= 0 {
				// time.Until can observe the deadline before ctx.Err() is set.
				return deadlineExceeded(ctx)
			}
			ms := int(rem / time.Millisecond)
			if ms < 1 {
				ms = 1
			}
			// Cap Poll at 25 ms even when the context deadline is far
			// away so ctx cancel is noticed promptly. A long remaining
			// deadline must not become a single uninterruptible Poll wait.
			if ms < timeout {
				timeout = ms
			}
		}
		pfd := []unix.PollFd{{Fd: unixConnectPollFd(fd), Events: unix.POLLOUT | unix.POLLERR}}
		n, err := unix.Poll(pfd, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		soerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if soerr != 0 {
			return unix.Errno(soerr)
		}
		return nil
	}
}

func unixConnectPollFd(fd int) int32 {
	if fd < 0 || fd > math.MaxInt32 {
		return -1
	}
	return int32(fd)
}

func deadlineExceeded(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return context.DeadlineExceeded
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
	setUnixSockaddrLen(&sa, n)
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
	backlog, err := xio.ListenBacklog(s)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := unix.Listen(fd, backlog); err != nil {
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
		if err := prepareUnixClientBind(bindPath, s); err != nil {
			return err
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
		var created unixBindCreated
		if bindPath != "" {
			if err := unixBindPath(fd, bindPath, tight); err != nil {
				logx.CloseErr(unix.Close(fd))
				return err
			}
			created = rememberUnixBindCreated(bindPath)
		}
		if err := unixConnectPath(cctx, fd, path, tight); err != nil {
			logx.CloseErr(unix.Close(fd))
			created.unlink()
			return err
		}
		nfd, err := dupFD(fd)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			created.unlink()
			return err
		}
		f := os.NewFile(uintptr(nfd), path)
		c, err := net.FileConn(f)
		logx.CloseQuiet(f)
		logx.CloseErr(unix.Close(fd))
		if err != nil {
			created.unlink()
			return err
		}
		conn = c
		return nil
	})
	return conn, err
}
