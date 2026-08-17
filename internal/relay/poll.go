package relay

import "errors"

// errPollIdle means the wait timed out or the fd was not readable yet; retry.
var errPollIdle = errors.New("poll idle")
