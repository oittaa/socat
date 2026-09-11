package relay

import "errors"

// errPollIdle means the wait timed out or the fd was not readable yet; retry.
var errPollIdle = errors.New("poll idle")

// streamNeedsExplicitPoll reports whether an endpoint has I/O that should be
// readiness-checked before each transfer block. Regular files and net.Conn
// already have efficient blocking semantics; non-regular files and custom
// raw-FD streams retain select-style backpressure needed by STALL
// and low-level endpoints.
func streamNeedsExplicitPoll(s Stream) bool {
	return PropsOf(s).NeedsPoll
}
