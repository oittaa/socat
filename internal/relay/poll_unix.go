//go:build linux || darwin

package relay

import (
	"context"
	"io"
	"math"
	"syscall"
	"time"

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

// pollWait is the poll(2) used by waitReadableAndWritable. Tests replace it
// to count wakeups; production keeps unix.Poll.
var pollWait = poll

const pollWaitTimeoutMs = 100

func idleClockSleep() {
	deadline := time.Now().Add(idleWatchInterval)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		timeoutMs := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if _, err := poll(nil, timeoutMs); err != syscall.EINTR {
			return
		}
	}
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
// (select-style STALL backpressure). If dst is closed/errored without being writable,
// return an error without reading (preserve unread peer data — needed for STALL).
func waitReadableAndWritable(ctx context.Context, srcFD, dstFD int) error {
	srcReady := false
	dstReady := false
	// POLLERR/POLLHUP/POLLNVAL are reported even when Events is 0. After a
	// hangup is observed on a side that is already ready, drop that fd from
	// the wait set so combined readiness+hangup cannot busy-spin.
	omitSrcWait := false
	omitDstWait := false
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var pfds []unix.PollFd
		srcIdx, dstIdx := -1, -1
		if !omitSrcWait {
			ev := int16(0)
			if !srcReady {
				ev = pollIn
			}
			p, ok := pollFd(srcFD, ev)
			if !ok {
				return syscall.EBADF
			}
			srcIdx = len(pfds)
			pfds = append(pfds, p)
		}
		if !omitDstWait {
			ev := int16(0)
			if !dstReady {
				ev = pollOut
			}
			p, ok := pollFd(dstFD, ev)
			if !ok {
				return syscall.EBADF
			}
			dstIdx = len(pfds)
			pfds = append(pfds, p)
		}
		if len(pfds) == 0 {
			return syscall.EBADF
		}
		n, err := pollWait(pfds, pollWaitTimeoutMs) // timeout so we honour ctx
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		if srcIdx >= 0 && pfds[srcIdx].Revents&(pollErr|pollHup|pollNval) != 0 {
			omitSrcWait = true
		}
		if dstIdx >= 0 && pfds[dstIdx].Revents&(pollErr|pollHup|pollNval) != 0 {
			omitDstWait = true
		}

		src, srcOK := pollFd(srcFD, pollIn)
		dst, dstOK := pollFd(dstFD, pollOut)
		if !srcOK || !dstOK {
			return syscall.EBADF
		}
		confirm := []unix.PollFd{src, dst}
		if _, err := poll(confirm, 0); err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		srcRe := confirm[0].Revents
		dstRe := confirm[1].Revents
		if dstRe&(pollErr|pollHup|pollNval) != 0 && dstRe&pollOut == 0 {
			return io.ErrClosedPipe
		}
		if srcRe&(pollErr|pollHup|pollNval) != 0 && srcRe&pollIn == 0 {
			return nil
		}
		srcReady = srcRe&pollIn != 0
		dstReady = dstRe&pollOut != 0
		if srcRe&(pollErr|pollHup|pollNval) != 0 {
			omitSrcWait = true
		}
		if dstRe&(pollErr|pollHup|pollNval) != 0 {
			omitDstWait = true
		}
		if srcReady && dstReady {
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
