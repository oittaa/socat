package netopen

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func ancillaryBuffer(buf *[]byte, enabled bool) []byte {
	if !enabled {
		return nil
	}
	if *buf == nil {
		*buf = make([]byte, xio.AncillaryBufferSize)
	}
	return *buf
}

// copyOneshotFirst delivers a buffered *-RECVFROM datagram. An empty packet
// is EOF (null-eof, or a raw IPv4 header with no payload).
func copyOneshotFirst(p, first []byte) (int, error) {
	if len(first) == 0 {
		return 0, io.EOF
	}
	return copy(p, first), nil
}

// firstPacket is a datagram captured before the session conn is handed to
// the relay. pending is true even for a zero-length datagram.
type firstPacket struct {
	data    []byte
	pending bool
}

func newFirstPacket(data []byte) firstPacket {
	return firstPacket{data: data, pending: true}
}

func (f *firstPacket) take() (data []byte, ok bool) {
	if f == nil || !f.pending {
		return nil, false
	}
	f.pending = false
	data = f.data
	f.data = nil
	return data, true
}

// sharedWriteDeadline is the per-child write deadline for sockets shared
// across fork sessions. The listener's write lock is separate.
type sharedWriteDeadline struct {
	mu       sync.Mutex
	deadline time.Time
}

func (w *sharedWriteDeadline) set(t time.Time) {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
}

func (w *sharedWriteDeadline) get() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deadline
}

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
