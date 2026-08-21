//go:build linux

package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type zeroCopyEndpointKind uint8

const (
	zeroCopyRegularFile zeroCopyEndpointKind = iota + 1
	zeroCopyStreamSocket
)

// linuxZeroCopy owns duplicated descriptors. Duplicating while Transfer still
// owns open Stream values avoids racing Fd/SyscallConn with cancellation, and
// lets the copy loop use nonblocking kernel syscalls without bypassing Go's
// descriptor lifecycle.
type linuxZeroCopy struct {
	srcFD   int
	dstFD   int
	srcKind zeroCopyEndpointKind
	dstKind zeroCopyEndpointKind
}

func prepareZeroCopy(src, dst Stream) zeroCopyPlan {
	rawSrc, ok := unwrapZeroCopyReader(src)
	if !ok {
		return nil
	}
	rawDst, ok := unwrapZeroCopyWriter(dst)
	if !ok {
		return nil
	}

	srcFD, srcKind, ok := duplicateZeroCopyFD(rawSrc)
	if !ok {
		return nil
	}
	dstFD, dstKind, ok := duplicateZeroCopyFD(rawDst)
	if !ok {
		_ = unix.Close(srcFD)
		return nil
	}

	// splice(2) cannot write to a regular file opened with O_APPEND.
	if dstKind == zeroCopyRegularFile {
		flags, err := unix.FcntlInt(uintptr(dstFD), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_APPEND != 0 {
			_ = unix.Close(srcFD)
			_ = unix.Close(dstFD)
			return nil
		}
	}

	// File-to-file copying is not a relay hot path and has filesystem-specific
	// copy_file_range/splice behavior. Retain the configured-buffer semantics.
	if srcKind == zeroCopyRegularFile && dstKind == zeroCopyRegularFile {
		_ = unix.Close(srcFD)
		_ = unix.Close(dstFD)
		return nil
	}

	return &linuxZeroCopy{
		srcFD: srcFD, dstFD: dstFD,
		srcKind: srcKind, dstKind: dstKind,
	}
}

// duplicateZeroCopyFD dups the endpoint's descriptor for exclusive kernel
// use; v is the concrete *os.File / *net.TCPConn / *net.UnixConn produced by
// the unwrap helpers.
func duplicateZeroCopyFD(v syscall.Conn) (int, zeroCopyEndpointKind, bool) {
	var kind zeroCopyEndpointKind
	switch value := v.(type) {
	case *os.File:
		info, err := value.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return -1, 0, false
		}
		kind = zeroCopyRegularFile
	case *net.TCPConn:
		kind = zeroCopyStreamSocket
	case *net.UnixConn:
		// A UnixConn also represents SOCK_DGRAM and SOCK_SEQPACKET. Only the
		// byte-stream network preserves relay block semantics.
		if unixConnNetwork(value) != "unix" {
			return -1, 0, false
		}
		kind = zeroCopyStreamSocket
	default:
		return -1, 0, false
	}

	raw, err := v.SyscallConn()
	if err != nil {
		return -1, 0, false
	}
	dupFD := -1
	var dupErr error
	if err := raw.Control(func(fd uintptr) {
		dupFD, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil || dupErr != nil || dupFD < 0 {
		if dupFD >= 0 {
			_ = unix.Close(dupFD)
		}
		return -1, 0, false
	}
	return dupFD, kind, true
}

func unixConnNetwork(c *net.UnixConn) string {
	if addr := c.LocalAddr(); addr != nil {
		return addr.Network()
	}
	if addr := c.RemoteAddr(); addr != nil {
		return addr.Network()
	}
	return ""
}

func (z *linuxZeroCopy) Close() error {
	first := unix.Close(z.srcFD)
	if err := unix.Close(z.dstFD); first == nil {
		first = err
	}
	return first
}

func (z *linuxZeroCopy) Copy(ctx context.Context, onRead, onWrite func(int64)) error {
	if z.srcKind == zeroCopyRegularFile && z.dstKind == zeroCopyStreamSocket {
		return z.copySendfile(ctx, onRead, onWrite)
	}
	return z.copySplice(ctx, onRead, onWrite)
}

const zeroCopyChunk = 1 << 20

func (z *linuxZeroCopy) copySendfile(ctx context.Context, onRead, onWrite func(int64)) error {
	written := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Sendfile(z.dstFD, z.srcFD, nil, zeroCopyChunk)
		if n > 0 {
			n64 := int64(n)
			written += n64
			onRead(n64)
			onWrite(n64)
		}
		switch {
		case err == nil && n == 0:
			return nil
		case err == nil:
			continue
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			if waitErr := waitZeroCopyFD(ctx, z.dstFD, unix.POLLOUT); waitErr != nil {
				return waitErr
			}
		case isZeroCopyUnsupportedError(err) && written == 0:
			return errZeroCopyUnsupported
		default:
			return err
		}
	}
}

func (z *linuxZeroCopy) copySplice(ctx context.Context, onRead, onWrite func(int64)) error {
	pipeFDs := []int{-1, -1}
	if err := unix.Pipe2(pipeFDs, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return errZeroCopyUnsupported
	}
	// Linux creates comparatively small pipe buffers by default. Match the Go
	// runtime's splice path and request the kernel's usual 1 MiB maximum; a
	// smaller buffer remains correct when the request is not permitted.
	_, _ = unix.FcntlInt(uintptr(pipeFDs[0]), unix.F_SETPIPE_SZ, zeroCopyChunk)
	defer func() {
		_ = unix.Close(pipeFDs[0])
		_ = unix.Close(pipeFDs[1])
	}()

	written := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Splice(z.srcFD, nil, pipeFDs[1], nil, zeroCopyChunk, unix.SPLICE_F_NONBLOCK)
		n64 := int64(n)
		if n64 > 0 {
			onRead(n64)
			left := n64
			for left > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				pumped, pumpErr := unix.Splice(pipeFDs[0], nil, z.dstFD, nil, int(left), unix.SPLICE_F_NONBLOCK)
				pumped64 := int64(pumped)
				if pumped64 > 0 {
					left -= pumped64
					written += pumped64
					onWrite(pumped64)
				}
				switch {
				case pumpErr == nil && pumped64 > 0:
					continue
				case errors.Is(pumpErr, unix.EINTR):
					continue
				case errors.Is(pumpErr, unix.EAGAIN), pumpErr == nil && pumped64 == 0:
					if waitErr := waitZeroCopyFD(ctx, z.dstFD, unix.POLLOUT); waitErr != nil {
						return waitErr
					}
				default:
					// Source data is already in the pipe, so falling back here would
					// silently discard it. Report the real error instead.
					return pumpErr
				}
			}
		}

		switch {
		case err == nil && n64 == 0:
			return nil
		case err == nil:
			continue
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			if waitErr := waitZeroCopyFD(ctx, z.srcFD, unix.POLLIN); waitErr != nil {
				if errors.Is(waitErr, io.EOF) {
					return nil
				}
				return waitErr
			}
		case isZeroCopyUnsupportedError(err) && written == 0 && n64 == 0:
			return errZeroCopyUnsupported
		default:
			return err
		}
	}
}

func isZeroCopyUnsupportedError(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

func waitZeroCopyFD(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		pfd, ok := pollFd(fd, events)
		if !ok {
			return syscall.EBADF
		}
		fds := []unix.PollFd{pfd}
		n, err := unix.Poll(fds, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		revents := fds[0].Revents
		if revents&events != 0 {
			return nil
		}
		if revents&unix.POLLNVAL != 0 {
			return syscall.EBADF
		}
		if events == unix.POLLIN && revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return io.EOF
		}
		if events == unix.POLLOUT && revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return io.ErrClosedPipe
		}
	}
}
