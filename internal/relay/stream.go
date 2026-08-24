package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
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

// streamSession is the generation counter shared by sequential sessionWraps on
// one reused stream (LISTEN,fork + end-close / FILE append). Each wrap
// snapshots a generation at construction; a later wrap makes the previous wrap
// stale so it cannot clear deadlines the next session installed.
type streamSession struct {
	gen atomic.Uint64
}

// sharedStream holds streamSession for sequential NoClose transfers. Callers
// that reuse a stream across Transfer sessions must keep this wrapper.
type sharedStream struct {
	Stream
	session *streamSession
}

func (s *sharedStream) UnwrapStream() Stream         { return s.Stream }
func (s *sharedStream) UnwrapZeroCopyStream() Stream { return s.Stream }

// ShareStream returns a stream that sequential NoClose session wraps can
// coordinate through a generation counter. It is idempotent: wrapping an
// already-shared stream is a no-op.
func ShareStream(inner Stream) Stream {
	if inner == nil {
		return nil
	}
	if findSharedStream(inner) != nil {
		return inner
	}
	return &sharedStream{Stream: inner, session: &streamSession{}}
}

func findSharedStream(inner Stream) *sharedStream {
	var found *sharedStream
	walkStreamCapabilities(inner, func(value any) bool {
		s, ok := value.(*sharedStream)
		if ok {
			found = s
		}
		return ok
	}, func(value any) []any {
		return regularStreamChildren(value, streamBoth)
	})
	return found
}

func sessionOf(inner Stream) *streamSession {
	if s := findSharedStream(inner); s != nil {
		return s.session
	}
	return &streamSession{}
}

// sessionWrap decouples a transfer session from a shared underlying stream.
// Close aborts this session and pokes a short deadline to wake blocked I/O.
// The next session starts with a new generation and drops leftover deadlines
// at construction, so Close does not sleep waiting for the poke to land.
type sessionWrap struct {
	inner   Stream
	done    chan struct{}
	once    sync.Once
	session *streamSession
	myGen   uint64
}

func newSessionWrap(inner Stream) *sessionWrap {
	inner = ShareStream(inner)
	session := sessionOf(inner)
	myGen := session.gen.Add(1)
	// Drop leftover poke deadlines from the previous session before this one
	// starts I/O or a caller installs timeout=.
	setStreamReadDeadline(inner, time.Time{})
	_ = setStreamWriteDeadline(inner, time.Time{})
	return &sessionWrap{inner: inner, done: make(chan struct{}), session: session, myGen: myGen}
}

func (s *sessionWrap) UnwrapStream() Stream { return s.inner }

func (s *sessionWrap) stale() bool {
	if s.session.gen.Load() != s.myGen {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
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
		if s.stale() {
			return 0, io.EOF
		}
		if usePoll {
			err := waitPollRead(fd, 50)
			if s.stale() {
				return 0, io.EOF
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
		if s.stale() {
			// Do not clear deadlines: the next session may already own them.
			return 0, io.EOF
		}
		if !usePoll {
			setStreamReadDeadline(s.inner, time.Time{})
		}
		if err == nil {
			return nr, nil
		}
		if isTimeoutErr(err) {
			continue
		}
		return nr, err
	}
}

func (s *sessionWrap) Write(p []byte) (int, error) {
	written := 0
	for {
		if s.stale() {
			return written, io.ErrClosedPipe
		}
		// Windows has no poll path. Bound each write so Close can cancel a
		// session without closing the shared end-close stream underneath it.
		deadlineSet := !canPoll() && setStreamWriteDeadline(s.inner, time.Now().Add(50*time.Millisecond))
		nw, err := s.inner.Write(p[written:])
		written += nw
		if s.stale() {
			return written, io.ErrClosedPipe
		}
		if deadlineSet {
			_ = setStreamWriteDeadline(s.inner, time.Time{})
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
		// Wake blocked I/O without waiting for it to observe the poke. The
		// next sessionWrap takes a new generation and clears leftover
		// deadlines at construction; a stale wrap must not clear them.
		now := time.Now().Add(time.Millisecond)
		setStreamReadDeadline(s.inner, now)
		_ = setStreamWriteDeadline(s.inner, now)
	})
	return nil
}

func (s *sessionWrap) ShutdownWrite() error {
	// NoCloseLeft/Right: do not half-close the shared underlying stream
	// (classic EXEC,end-close + LISTEN,fork keeps cat stdin open across accepts).
	return nil
}

// --- capability traversal over wrapped streams ---

// SetStreamReadDeadline sets a read deadline on the first stream layer that
// supports one. Layers that report os.ErrNoDeadline are skipped so split
// streams can expose a deadline-capable reader below an FDStream wrapper.
func SetStreamReadDeadline(s Stream, deadline time.Time) (bool, error) {
	var deadlineErr error
	found := walkStreamCapabilities(s, func(value any) bool {
		d, ok := value.(interface{ SetReadDeadline(time.Time) error })
		if !ok {
			return false
		}
		err := d.SetReadDeadline(deadline)
		if errors.Is(err, os.ErrNoDeadline) {
			return false
		}
		deadlineErr = err
		return true
	}, func(value any) []any {
		return regularStreamChildren(value, streamRead)
	})
	return found, deadlineErr
}

// setStreamReadDeadline is the best-effort form used by cancellation paths.
func setStreamReadDeadline(s Stream, deadline time.Time) {
	_, _ = SetStreamReadDeadline(s, deadline)
}

// SetStreamWriteDeadline is the write-side counterpart of
// SetStreamReadDeadline.
func SetStreamWriteDeadline(s Stream, deadline time.Time) (bool, error) {
	var deadlineErr error
	found := walkStreamCapabilities(s, func(value any) bool {
		d, ok := value.(interface{ SetWriteDeadline(time.Time) error })
		if !ok {
			return false
		}
		err := d.SetWriteDeadline(deadline)
		if errors.Is(err, os.ErrNoDeadline) {
			return false
		}
		deadlineErr = err
		return true
	}, func(value any) []any {
		return regularStreamChildren(value, streamWrite)
	})
	return found, deadlineErr
}

func setStreamWriteDeadline(s Stream, deadline time.Time) bool {
	found, err := SetStreamWriteDeadline(s, deadline)
	return found && err == nil
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if os.IsTimeout(err) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var to interface{ Timeout() bool }
	return errors.As(err, &to) && to.Timeout()
}

func pokeReadDeadline(s Stream) {
	// Try SetReadDeadline on known types; clear after a moment.
	set := func(d interface{ SetReadDeadline(time.Time) error }) {
		_ = d.SetReadDeadline(time.Now())
		go func() {
			time.Sleep(10 * time.Millisecond)
			_ = d.SetReadDeadline(time.Time{})
		}()
	}
	walkStreamCapabilities(s, func(value any) bool {
		if _, ok := value.(*sessionWrap); ok {
			// sessionWrap.Close pokes inner deadlines; generation + the next
			// wrap's constructor drop leftovers. Do not async-clear through
			// this layer (that would race the next session's timeout).
			return true
		}
		d, ok := value.(interface{ SetReadDeadline(time.Time) error })
		if ok {
			set(d)
		}
		return ok
	}, func(value any) []any {
		return regularStreamChildren(value, streamRead)
	})
}

func streamReadFD(s Stream) int {
	return streamFD(s, streamRead)
}

func streamWriteFD(s Stream) int {
	return streamFD(s, streamWrite)
}

func streamFD(s Stream, direction streamDirection) int {
	fd := -1
	walkStreamCapabilities(s, func(value any) bool {
		fd = streamValueFD(value)
		return fd >= 0
	}, func(value any) []any {
		return regularStreamChildren(value, direction)
	})
	return fd
}

func streamValueFD(value any) int {
	if fd := ioFD(value); fd >= 0 {
		return fd
	}
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}
	conn, ok := value.(syscallConn)
	if !ok {
		return -1
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	_ = raw.Control(func(rawFD uintptr) { fd = int(rawFD) })
	return fd
}

func ioFD(v any) int {
	if v == nil {
		return -1
	}
	if f, ok := v.(*os.File); ok {
		// Accept FD 0 (stdin) — was incorrectly rejected by >0 checks.
		return int(f.Fd())
	}
	if f, ok := v.(interface{ Fd() uintptr }); ok {
		return int(f.Fd())
	}
	return -1
}
