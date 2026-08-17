//go:build unix

package relay

import "golang.org/x/sys/unix"

const (
	pollIn   = unix.POLLIN
	pollOut  = unix.POLLOUT
	pollHup  = unix.POLLHUP
	pollErr  = unix.POLLERR
	pollNval = unix.POLLNVAL
)

func poll(fds []pollfd, timeoutMs int) (int, error) {
	pf := make([]unix.PollFd, len(fds))
	for i, f := range fds {
		pf[i] = unix.PollFd{Fd: f.Fd, Events: f.Events}
	}
	n, err := unix.Poll(pf, timeoutMs)
	for i := range fds {
		fds[i].Revents = pf[i].Revents
	}
	return n, err
}
