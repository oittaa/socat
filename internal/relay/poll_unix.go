//go:build unix

package relay

import (
	"context"
	"io"
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	pollIn   = unix.POLLIN
	pollOut  = unix.POLLOUT
	pollHup  = unix.POLLHUP
	pollErr  = unix.POLLERR
	pollNval = unix.POLLNVAL
)

func canPoll() bool { return true }

func pollFd(fd int, events int16) (unix.PollFd, bool) {
	if fd < 0 || fd > math.MaxInt32 {
		return unix.PollFd{}, false
	}
	return unix.PollFd{Fd: int32(fd), Events: events}, true
}

func poll(fds []unix.PollFd, timeoutMs int) (int, error) {
	return unix.Poll(fds, timeoutMs)
}

// waitPollRead waits until fd is readable. errPollIdle means retry.
// io.EOF means hang-up / error without POLLIN.
func waitPollRead(fd int, timeoutMs int) error {
	pfd, ok := pollFd(fd, pollIn)
	if !ok {
		return errPollIdle
	}
	// Poll must see a slice element; a value copy leaves Revents at 0.
	pfds := []unix.PollFd{pfd}
	n, err := poll(pfds, timeoutMs)
	if err != nil {
		if err == syscall.EINTR {
			return errPollIdle
		}
		return err
	}
	if n <= 0 {
		return errPollIdle
	}
	re := pfds[0].Revents
	if re&pollIn == 0 {
		if re&(pollHup|pollErr|pollNval) != 0 {
			return io.EOF
		}
		return errPollIdle
	}
	return nil
}

// waitReadableAndWritable waits until src is readable and dst is writable
// (classic select backpressure). If dst is closed/errored without being writable,
// return an error without reading (preserve unread peer data — needed for STALL).
func waitReadableAndWritable(ctx context.Context, srcFD, dstFD int) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		src, srcOK := pollFd(srcFD, pollIn)
		dst, dstOK := pollFd(dstFD, pollOut)
		if !srcOK || !dstOK {
			return syscall.EBADF
		}
		pfd := []unix.PollFd{src, dst}
		n, err := poll(pfd, 100) // 100ms so we honour ctx
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		srcRe := pfd[0].Revents
		dstRe := pfd[1].Revents
		if dstRe&(pollErr|pollHup|pollNval) != 0 && dstRe&pollOut == 0 {
			return io.ErrClosedPipe
		}
		if srcRe&(pollErr|pollHup|pollNval) != 0 && srcRe&pollIn == 0 {
			return nil
		}
		if srcRe&pollIn != 0 && dstRe&pollOut != 0 {
			return nil
		}
	}
}

func waitWritable(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		dst, ok := pollFd(fd, pollOut)
		if !ok {
			return syscall.EBADF
		}
		pfds := []unix.PollFd{dst}
		n, err := poll(pfds, 100)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		revents := pfds[0].Revents
		if revents&pollOut != 0 {
			return nil
		}
		if revents&(pollErr|pollHup|pollNval) != 0 {
			return io.ErrClosedPipe
		}
	}
}
