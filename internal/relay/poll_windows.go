//go:build windows

package relay

import "time"

const (
	pollIn   = 0x001
	pollOut  = 0x004
	pollHup  = 0x010
	pollErr  = 0x008
	pollNval = 0x020
)

// poll has no WSAPoll wrapper in x/sys/windows; wait then treat requested
// events as ready so Transfer can proceed with Read/Write.
func poll(fds []pollfd, timeoutMs int) (int, error) {
	if timeoutMs > 0 {
		time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
	}
	for i := range fds {
		fds[i].Revents = fds[i].Events
	}
	return len(fds), nil
}
