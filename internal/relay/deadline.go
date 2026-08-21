package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

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

// isBenignClose reports I/O errors that mean the peer/stream was already closed
// (common with PTY/socketpair half-close races). Treat as clean EOF.
func isBenignClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	return errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EPIPE)
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
