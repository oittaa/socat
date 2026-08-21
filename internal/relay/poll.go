package relay

import (
	"errors"
	"os"
)

// errPollIdle means the wait timed out or the fd was not readable yet; retry.
var errPollIdle = errors.New("poll idle")

// streamNeedsExplicitPoll reports whether an endpoint has I/O that should be
// readiness-checked before each transfer block. Regular files and net.Conn
// already have efficient blocking semantics; non-regular files and custom
// raw-FD streams retain the classic select-style backpressure needed by STALL
// and low-level endpoints.
func streamNeedsExplicitPoll(s Stream) bool {
	return streamNeedsExplicitPollDepth(s, 0)
}

func streamNeedsExplicitPollDepth(s Stream, depth int) bool {
	if s == nil || depth >= 8 {
		return false
	}
	if _, ok := s.(fdProvider); ok {
		return true
	}
	if fs, ok := s.(FDStream); ok {
		return ioNeedsExplicitPoll(fs.R, depth+1) || ioNeedsExplicitPoll(fs.W, depth+1)
	}
	if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
		return streamNeedsExplicitPollDepth(u.UnwrapStream(), depth+1)
	}
	return false
}

func ioNeedsExplicitPoll(v any, depth int) bool {
	if v == nil {
		return false
	}
	if f, ok := v.(*os.File); ok {
		info, err := f.Stat()
		return err != nil || !info.Mode().IsRegular()
	}
	if s, ok := v.(Stream); ok {
		return streamNeedsExplicitPollDepth(s, depth)
	}
	_, ok := v.(fdProvider)
	return ok
}
