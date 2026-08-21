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

// --- capability traversal over wrapped streams ---

// setStreamReadDeadline sets a read deadline on the first layer that supports one.
func setStreamReadDeadline(s Stream, deadline time.Time) {
	if d, ok := s.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(deadline)
		return
	}
	if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
		setStreamReadDeadline(u.UnwrapStream(), deadline)
		return
	}
	if ns, ok := s.(NetStream); ok {
		if c, ok := ns.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = c.SetReadDeadline(deadline)
		}
		return
	}
	if fs, ok := s.(FDStream); ok {
		if d, ok := fs.R.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = d.SetReadDeadline(deadline)
		}
		return
	}
}

func setStreamWriteDeadline(s Stream, deadline time.Time) bool {
	if d, ok := s.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(deadline) == nil
	}
	if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
		return setStreamWriteDeadline(u.UnwrapStream(), deadline)
	}
	if ns, ok := s.(NetStream); ok {
		if c, ok := ns.Conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			return c.SetWriteDeadline(deadline) == nil
		}
		return false
	}
	if fs, ok := s.(FDStream); ok {
		if d, ok := fs.W.(interface{ SetWriteDeadline(time.Time) error }); ok {
			return d.SetWriteDeadline(deadline) == nil
		}
		return false
	}
	if rwc, ok := s.(RWCStream); ok {
		if d, ok := rwc.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
			return d.SetWriteDeadline(deadline) == nil
		}
	}
	return false
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
	if sw, ok := s.(*sessionWrap); ok {
		// sessionWrap.Close sets and synchronously clears both deadlines.
		_ = sw
		return
	}
	// Streams that implement SetReadDeadline themselves (e.g. SOCKET raw dgram).
	if d, ok := s.(interface{ SetReadDeadline(time.Time) error }); ok {
		set(d)
		return
	}
	if t, ok := s.(NetStream); ok {
		if c, ok := t.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			set(c)
			return
		}
	}
	if t, ok := s.(FDStream); ok {
		if d, ok := t.R.(interface{ SetReadDeadline(time.Time) error }); ok {
			set(d)
			return
		}
	}
	// Unwrap embedded Stream (endCloseStream, etc.)
	if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
		pokeReadDeadline(u.UnwrapStream())
	}
}

func streamReadFD(s Stream) int {
	// Unwrap nested Streams (dual FDStream wraps Stream interfaces).
	for i := 0; i < 6 && s != nil; i++ {
		if fs, ok := s.(FDStream); ok {
			if f := ioFD(fs.R); f >= 0 {
				return f
			}
			// R may itself be a Stream
			if rs, ok := fs.R.(Stream); ok {
				s = rs
				continue
			}
		}
		if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
			s = u.UnwrapStream()
			continue
		}
		break
	}
	return streamAnyFD(s)
}

func streamWriteFD(s Stream) int {
	for i := 0; i < 6 && s != nil; i++ {
		if fs, ok := s.(FDStream); ok {
			if f := ioFD(fs.W); f >= 0 {
				return f
			}
			if ws, ok := fs.W.(Stream); ok {
				s = ws
				continue
			}
		}
		if u, ok := s.(interface{ UnwrapStream() Stream }); ok {
			s = u.UnwrapStream()
			continue
		}
		break
	}
	return streamAnyFD(s)
}

func streamAnyFD(s Stream) int {
	if f, ok := s.(fdProvider); ok {
		fd := int(f.Fd())
		if fd >= 0 {
			return fd
		}
	}
	if ns, ok := s.(NetStream); ok {
		type sc interface {
			SyscallConn() (syscall.RawConn, error)
		}
		if c, ok := ns.Conn.(sc); ok {
			rc, err := c.SyscallConn()
			if err == nil {
				var fd = -1
				_ = rc.Control(func(f uintptr) { fd = int(f) })
				if fd >= 0 {
					return fd
				}
			}
		}
	}
	if fs, ok := s.(FDStream); ok {
		if f := ioFD(fs.R); f >= 0 {
			return f
		}
		if f := ioFD(fs.W); f >= 0 {
			return f
		}
	}
	return -1
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
