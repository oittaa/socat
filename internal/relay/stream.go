package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
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
	// StreamProps is the relay-visible endpoint. Wrappers that embed Stream
	// forward it; wrappers that convert bytes clear zero-copy.
	StreamProps() Props
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

func (s *closeSerialStream) StreamProps() Props {
	return WithoutZeroCopy(PropsOf(s.Stream))
}

// sessionWrap decouples a transfer session from a shared underlying stream.
// Close aborts this session and pokes a short deadline to wake blocked I/O.
// It does not sleep or clear that poke: fork reuse is serialized (leftMu),
// Transfer waits for the copies to finish, and the next wrap drops leftover
// deadlines at construction.
type sessionWrap struct {
	inner  Stream
	shared *Shared // nil unless inner is reused by later sessions
	done   chan struct{}
	once   sync.Once
}

func newSessionWrap(inner Stream) *sessionWrap {
	// Drop leftover poke deadlines from the previous serialized session
	// before this one starts I/O or a caller installs timeout=.
	setStreamReadDeadline(inner, time.Time{})
	_ = setStreamWriteDeadline(inner, time.Time{})
	shared, _ := inner.(*Shared)
	return &sessionWrap{inner: inner, shared: shared, done: make(chan struct{})}
}

// Shared is a stream reused by serialized sessions. Input that one session
// read after it closed belongs to the next session, as does a read that
// Close could not interrupt.
type Shared struct {
	Stream
	mu      sync.Mutex
	pending []byte
	err     error
	reading chan struct{} // closed when the background read finishes
}

// NewShared wraps a stream that serialized sessions reuse.
func NewShared(s Stream) *Shared { return &Shared{Stream: s} }

func (s *Shared) UnwrapStream() Stream { return s.Stream }

// take returns input left by an earlier session, if any.
func (s *Shared) take(p []byte) (int, bool, error) {
	if s == nil {
		return 0, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, true, nil
	}
	if err := s.err; err != nil {
		s.err = nil
		return 0, true, err
	}
	return 0, false, nil
}

func (s *Shared) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0 || s.err != nil
}

// keep saves input that a closed session read.
func (s *Shared) keep(b []byte) {
	if s == nil || len(b) == 0 {
		return
	}
	s.mu.Lock()
	s.pending = append(s.pending, b...)
	s.mu.Unlock()
}

// background reads without a session so the read can outlive one. It
// returns a channel closed when input is ready for take.
func (s *Shared) background(size int) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) > 0 || s.err != nil {
		// An earlier read finished after the caller's take.
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	if s.reading == nil {
		done := make(chan struct{})
		s.reading = done
		go func() {
			buf := make([]byte, size)
			n, err := s.Read(buf)
			s.mu.Lock()
			s.pending = append(s.pending, buf[:n]...)
			s.err = err
			s.reading = nil
			s.mu.Unlock()
			close(done)
		}()
	}
	return s.reading
}

func (s *sessionWrap) UnwrapStream() Stream { return s.inner }

func (s *sessionWrap) StreamProps() Props {
	return WithoutZeroCopy(PropsOf(s.inner))
}

func (s *sessionWrap) closed() bool {
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
		fd = StreamReadFD(s.inner)
		if fd < 0 {
			usePoll = false
		}
	}
	for {
		if s.closed() {
			return 0, io.EOF
		}
		if n, ok, err := s.shared.take(p); ok {
			return n, err
		}
		if usePoll {
			err := waitPollRead(fd, 50)
			if s.closed() {
				return 0, io.EOF
			}
			if err != nil {
				if err == errPollIdle {
					continue
				}
				return 0, err
			}
		} else if ok, _ := SetStreamReadDeadline(s.inner, time.Now().Add(50*time.Millisecond)); !ok && s.shared != nil {
			// Close cannot interrupt this read, so it must outlive the session.
			select {
			case <-s.shared.background(len(p)):
				continue
			case <-s.done:
				return 0, io.EOF
			}
		}
		nr, err := s.inner.Read(p)
		if s.closed() {
			// Leave leftover poke/slice deadlines for the next serialized wrap.
			s.shared.keep(p[:nr])
			return 0, io.EOF
		}
		if !usePoll {
			setStreamReadDeadline(s.inner, time.Time{})
		}
		if err == nil {
			return nr, nil
		}
		if IsTimeoutErr(err) {
			continue
		}
		return nr, err
	}
}

func (s *sessionWrap) Write(p []byte) (int, error) {
	written := 0
	for {
		if s.closed() {
			return written, io.ErrClosedPipe
		}
		// Windows has no poll path. Bound each write so Close can cancel a
		// session without closing the shared end-close stream underneath it.
		deadlineSet := !canPoll() && setStreamWriteDeadline(s.inner, time.Now().Add(50*time.Millisecond))
		nw, err := s.inner.Write(p[written:])
		written += nw
		if s.closed() {
			return written, io.ErrClosedPipe
		}
		if deadlineSet {
			_ = setStreamWriteDeadline(s.inner, time.Time{})
		}
		if written == len(p) {
			return written, nil
		}
		if deadlineSet && IsTimeoutErr(err) {
			continue
		}
		return written, err
	}
}

func (s *sessionWrap) Close() error {
	s.once.Do(func() {
		close(s.done)
		// Wake blocked I/O. The next serialized sessionWrap clears leftovers.
		now := time.Now().Add(time.Millisecond)
		setStreamReadDeadline(s.inner, now)
		_ = setStreamWriteDeadline(s.inner, now)
	})
	return nil
}

func (s *sessionWrap) ShutdownWrite() error {
	// NoCloseLeft/Right: do not half-close the shared underlying stream
	// (EXEC,end-close + LISTEN,fork keeps cat stdin open across accepts).
	return nil
}

// --- stream properties ---

// SetStreamReadDeadline sets a read deadline when the stream exposes one.
// os.ErrNoDeadline is treated as no deadline support.
func SetStreamReadDeadline(s Stream, deadline time.Time) (bool, error) {
	set := readDeadlineOf(s)
	if set == nil {
		return false, nil
	}
	err := set(deadline)
	if errors.Is(err, os.ErrNoDeadline) {
		return false, nil
	}
	return true, err
}

// setStreamReadDeadline is the best-effort form used by cancellation paths.
func setStreamReadDeadline(s Stream, deadline time.Time) {
	_, _ = SetStreamReadDeadline(s, deadline)
}

// SetStreamWriteDeadline is the write-side counterpart of
// SetStreamReadDeadline.
func SetStreamWriteDeadline(s Stream, deadline time.Time) (bool, error) {
	set := writeDeadlineOf(s)
	if set == nil {
		return false, nil
	}
	err := set(deadline)
	if errors.Is(err, os.ErrNoDeadline) {
		return false, nil
	}
	return true, err
}

func setStreamWriteDeadline(s Stream, deadline time.Time) bool {
	found, err := SetStreamWriteDeadline(s, deadline)
	return found && err == nil
}

// IsTimeoutErr reports whether err is a timeout. nil is false. It
// recognizes os.ErrDeadlineExceeded, context.DeadlineExceeded, os.IsTimeout,
// and any wrapped error that implements Timeout() bool — not only net.Error.
func IsTimeoutErr(err error) bool {
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
	if hasSessionWrap(s) {
		// sessionWrap.Close pokes inner deadlines; the next serialized
		// wrap clears leftovers at construction. Transfer wraps that
		// session in closeSerialStream before cancellation.
		return
	}
	set := readDeadlineOf(s)
	if set == nil {
		return
	}
	_ = set(time.Now())
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = set(time.Time{})
	}()
}

func hasSessionWrap(s Stream) bool {
	return sessionOf(s) != nil
}

// sharedPending reports input an earlier session left for this one. Polling
// the descriptor would not see it.
func sharedPending(s Stream) bool {
	w := sessionOf(s)
	return w != nil && w.shared != nil && w.shared.hasPending()
}

func sessionOf(s Stream) *sessionWrap {
	cur := s
	for range 32 {
		if cur == nil {
			return nil
		}
		if w, ok := cur.(*sessionWrap); ok {
			return w
		}
		u, ok := cur.(interface{ UnwrapStream() Stream })
		if !ok {
			return nil
		}
		next := u.UnwrapStream()
		if next == nil || next == cur {
			return nil
		}
		cur = next
	}
	return nil
}

// StreamReadFD returns the underlying read descriptor, or -1.
func StreamReadFD(s Stream) int {
	return PropsOf(s).ReadFD
}

// StreamWriteFD returns the underlying write descriptor, or -1.
func StreamWriteFD(s Stream) int {
	return PropsOf(s).WriteFD
}

// readDeadlineOf finds SetReadDeadline without Inspect. Cancel pokes
// deadlines while the peer Close/ShutdownWrite runs; File.Stat and File.Fd
// are not safe concurrent with Close.
func readDeadlineOf(s Stream) func(time.Time) error {
	return deadlineOf(s, true)
}

func writeDeadlineOf(s Stream) func(time.Time) error {
	return deadlineOf(s, false)
}

func deadlineOf(s Stream, read bool) func(time.Time) error {
	var cur any = s
	for range 32 {
		if cur == nil {
			return nil
		}
		if read {
			if d, ok := cur.(interface{ SetReadDeadline(time.Time) error }); ok {
				return d.SetReadDeadline
			}
		} else if d, ok := cur.(interface{ SetWriteDeadline(time.Time) error }); ok {
			return d.SetWriteDeadline
		}
		switch v := cur.(type) {
		case interface{ UnwrapStream() Stream }:
			cur = v.UnwrapStream()
		case FDStream:
			if read {
				cur = v.R
			} else {
				cur = v.W
			}
		case NetStream:
			cur = v.Conn
		case RWCStream:
			cur = v.ReadWriteCloser
		case interface{ UnwrapReader() io.Reader }:
			if !read {
				return nil
			}
			next := v.UnwrapReader()
			if next == nil || any(next) == cur {
				return nil
			}
			cur = next
		default:
			return nil
		}
	}
	return nil
}

func streamValueFD(value any) int {
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if conn, ok := value.(syscallConn); ok {
		raw, err := conn.SyscallConn()
		if err == nil {
			fd := -1
			_ = raw.Control(func(rawFD uintptr) { fd = int(rawFD) })
			if fd >= 0 {
				return fd
			}
		}
	}
	return ioFD(value)
}

func ioFD(v any) int {
	if v == nil {
		return -1
	}
	if _, ok := v.(*os.File); ok {
		// File.Fd() is not safe concurrent with Close. SyscallConn.Control
		// above is the path for *os.File.
		return -1
	}
	if f, ok := v.(interface{ Fd() uintptr }); ok {
		return int(f.Fd())
	}
	return -1
}
