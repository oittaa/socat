package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Stream is a bidirectional byte stream with optional half-close.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	// ShutdownWrite half-closes the write side (like shutdown(SHUT_WR)).
	// If not supported, Close may be used by the relay after linger.
	ShutdownWrite() error
}

// fdProvider is optionally implemented by streams backed by a real file descriptor.
type fdProvider interface {
	Fd() uintptr
}

// zeroCopyPlan is prepared before the cancellation goroutine can close either
// stream. Implementations own any duplicated descriptors and report read and
// write progress so idle timeouts and live statistics retain their normal
// semantics while data remains in the kernel.
type zeroCopyPlan interface {
	Copy(ctx context.Context, onRead, onWrite func(int64)) error
	Close() error
}

var errZeroCopyUnsupported = errors.New("zero-copy transfer unsupported")

// NetStream wraps a net.Conn as a Stream.
type NetStream struct {
	net.Conn
}

func (s NetStream) ShutdownWrite() error {
	type closer interface {
		CloseWrite() error
	}
	if cw, ok := s.Conn.(closer); ok {
		return cw.CloseWrite()
	}
	// For conns without CloseWrite, no-op half-close (full Close left to caller).
	return nil
}

// RWCStream wraps an io.ReadWriteCloser without half-close support.
type RWCStream struct {
	io.ReadWriteCloser
}

func (s RWCStream) ShutdownWrite() error { return nil }

// FDStream is a ReadWriteCloser with optional write closer.
type FDStream struct {
	R      io.Reader
	W      io.Writer
	C      io.Closer
	CloseW func() error
}

func (s FDStream) Read(p []byte) (int, error)  { return s.R.Read(p) }
func (s FDStream) Write(p []byte) (int, error) { return s.W.Write(p) }
func (s FDStream) Close() error {
	if s.C != nil {
		return s.C.Close()
	}
	return nil
}
func (s FDStream) ShutdownWrite() error {
	if s.CloseW != nil {
		return s.CloseW()
	}
	return nil
}

// closeSerialStream serializes the two descriptor-lifecycle operations while
// leaving data I/O concurrent so Close can interrupt blocked reads and writes.
type closeSerialStream struct {
	Stream
	mu sync.Mutex
}

func newCloseSerialStream(stream Stream) *closeSerialStream {
	return &closeSerialStream{Stream: stream}
}

func (s *closeSerialStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stream.Close()
}

func (s *closeSerialStream) ShutdownWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stream.ShutdownWrite()
}

func (s *closeSerialStream) UnwrapStream() Stream { return s.Stream }

// sessionWrap decouples a transfer session from a shared underlying stream.
// Close aborts this session; a short read deadline on the inner FD unblocks
// a stuck Read so the next session can reuse the shared stream.
type sessionWrap struct {
	inner Stream
	done  chan struct{}
	once  sync.Once
}

func newSessionWrap(inner Stream) *sessionWrap {
	return &sessionWrap{inner: inner, done: make(chan struct{})}
}

func (s *sessionWrap) Read(p []byte) (int, error) {
	// Unix: poll so Close can stop us (PTY masters ignore SetReadDeadline).
	// Windows: File.Fd() detaches IOCP and kills deadlines, so never call it;
	// use SetReadDeadline instead (pipes and sockets honour it).
	usePoll := canPoll()
	fd := -1
	if usePoll {
		fd = streamReadFD(s.inner)
		if fd < 0 {
			usePoll = false
		}
	}
	for {
		select {
		case <-s.done:
			return 0, io.EOF
		default:
		}
		if usePoll {
			err := waitPollRead(fd, 50)
			select {
			case <-s.done:
				return 0, io.EOF
			default:
			}
			if err != nil {
				if err == errPollIdle {
					continue
				}
				return 0, err
			}
		} else {
			setStreamReadDeadline(s.inner, time.Now().Add(50*time.Millisecond))
		}
		nr, err := s.inner.Read(p)
		if !usePoll {
			setStreamReadDeadline(s.inner, time.Time{})
		}
		if err == nil {
			select {
			case <-s.done:
				return 0, io.EOF
			default:
				return nr, nil
			}
		}
		if isTimeoutErr(err) {
			continue
		}
		select {
		case <-s.done:
			return 0, io.EOF
		default:
			return nr, err
		}
	}
}

func (s *sessionWrap) Write(p []byte) (int, error) {
	written := 0
	for {
		select {
		case <-s.done:
			return written, io.ErrClosedPipe
		default:
		}
		// Windows has no poll path. Bound each write so Close can cancel a
		// session without closing the shared end-close stream underneath it.
		deadlineSet := !canPoll() && setStreamWriteDeadline(s.inner, time.Now().Add(50*time.Millisecond))
		nw, err := s.inner.Write(p[written:])
		written += nw
		if deadlineSet {
			_ = setStreamWriteDeadline(s.inner, time.Time{})
		}
		select {
		case <-s.done:
			return written, io.ErrClosedPipe
		default:
		}
		if written == len(p) {
			return written, nil
		}
		if deadlineSet && isTimeoutErr(err) {
			continue
		}
		return written, err
	}
}

func (s *sessionWrap) Close() error {
	s.once.Do(func() {
		close(s.done)
		// Wake blocked I/O without permanently poisoning the shared stream.
		setStreamReadDeadline(s.inner, time.Now().Add(time.Millisecond))
		_ = setStreamWriteDeadline(s.inner, time.Now().Add(time.Millisecond))
		// Transfer waits for Close to finish before allowing the next fork
		// session to use this shared stream. Clear the deadlines synchronously
		// so the next session cannot inherit an already-expired deadline.
		time.Sleep(20 * time.Millisecond)
		setStreamReadDeadline(s.inner, time.Time{})
		_ = setStreamWriteDeadline(s.inner, time.Time{})
	})
	return nil
}

func (s *sessionWrap) ShutdownWrite() error {
	// NoCloseLeft/Right: do not half-close the shared underlying stream
	// (classic EXEC,end-close + LISTEN,fork keeps cat stdin open across accepts).
	return nil
}
