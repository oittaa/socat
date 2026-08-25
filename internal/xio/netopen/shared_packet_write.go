package netopen

import (
	"errors"
	"sync"
	"time"
)

// writeSharedPacket serializes writes that share a listener socket. The
// deadline belongs to the child session, so install it only while that child
// owns the write lock and clear it before another child can write.
func writeSharedPacket(
	mu *sync.Mutex,
	deadline time.Time,
	setDeadline func(time.Time) error,
	write func() (int, error),
) (int, error) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	if err := setDeadline(deadline); err != nil {
		return 0, err
	}
	n, writeErr := write()
	clearErr := setDeadline(time.Time{})
	return n, errors.Join(writeErr, clearErr)
}
