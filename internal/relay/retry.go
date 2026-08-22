package relay

import "errors"

// retryableIOError is implemented by an I/O layer that can safely repeat the
// operation after the reported error. It deliberately does not use
// net.Error.Timeout: accept, handshake, inactivity, and cancellation deadlines
// have terminating semantics.
type retryableIOError interface {
	Retryable() bool
}

func isRetryableIOError(err error) bool {
	if err == nil {
		return false
	}
	var retryable retryableIOError
	if errors.As(err, &retryable) && retryable.Retryable() {
		return true
	}
	return isWouldBlock(err)
}
