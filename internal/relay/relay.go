// Package relay implements bidirectional data transfer between two streams.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Config controls transfer behavior.
type Config struct {
	// BufferSize is the max bytes per read (classic -b, default 8192).
	BufferSize int
	// Linger is how long to wait after one side EOFs for the other direction (-t).
	Linger time.Duration
	// IdleTimeout is total inactivity timeout (-T); 0 means disabled.
	IdleTimeout time.Duration
	// Unidirectional: only left→right (-u) or right→left (-U).
	LeftToRight bool
	RightToLeft bool
	// Verbose dumps transferred data to Dump (text).
	Verbose bool
	// Hex dumps transferred data in hex.
	Hex bool
	// Dump is where -v/-x output goes (usually stderr).
	Dump io.Writer
	// RawLeft/RawRight: classic -r / -R binary dumps of transferred data.
	RawLeft  io.Writer // left→right
	RawRight io.Writer // right→left
	// Tracker receives live counters (SIGUSR1 / --statistics). If nil, Transfer
	// allocates one and registers it.
	Tracker *Tracker
	// OnStats is called with final counters if non-nil.
	OnStats func(Stats)
	// OnEOF is called once per direction when that side reaches EOF
	// (classic MULTIPLE_EOF: "socket N (fd X) is at EOF"). sock is 1=left, 2=right.
	OnEOF func(sock int, fd int)
	// NoCloseLeft/Right: on cancel, do not Close that stream (classic end-close
	// shared address across fork children).
	NoCloseLeft  bool
	NoCloseRight bool
}

// Stats holds transfer counters.
type Stats struct {
	BytesLR  uint64
	BytesRL  uint64
	BlocksLR uint64
	BlocksRL uint64
	Duration time.Duration
}

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
// When both ends provide FDs, Transfer waits for the destination to be writable
// before reading the source (classic select-based backpressure, needed for STALL).
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

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 8192)
		return &b
	},
}

func getBuf(size int) *[]byte {
	bp := bufPool.Get().(*[]byte)
	if cap(*bp) < size {
		b := make([]byte, size)
		return &b
	}
	*bp = (*bp)[:size]
	return bp
}

func putBuf(bp *[]byte) {
	bufPool.Put(bp)
}

// Transfer copies data bidirectionally between left and right until both directions finish.
func Transfer(ctx context.Context, left, right Stream, cfg Config) error {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 8192
	}
	if !cfg.LeftToRight && !cfg.RightToLeft {
		cfg.LeftToRight = true
		cfg.RightToLeft = true
	}
	if cfg.Linger < 0 {
		cfg.Linger = 500 * time.Millisecond // classic default 0.5s
	}

	start := time.Now()
	tr := cfg.Tracker
	if tr == nil {
		tr = &Tracker{LeftToRight: cfg.LeftToRight, RightToLeft: cfg.RightToLeft}
	} else {
		tr.LeftToRight = cfg.LeftToRight
		tr.RightToLeft = cfg.RightToLeft
	}
	RegisterTracker(tr)
	defer UnregisterTracker(tr)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Idle timeout watchdog
	var idleMu sync.Mutex
	lastActivity := time.Now()
	touch := func() {
		idleMu.Lock()
		lastActivity = time.Now()
		idleMu.Unlock()
	}
	if cfg.IdleTimeout > 0 {
		go func() {
			t := time.NewTicker(100 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					idleMu.Lock()
					idle := time.Since(lastActivity)
					idleMu.Unlock()
					if idle >= cfg.IdleTimeout {
						cancel()
						return
					}
				}
			}
		}()
	}

	type dirResult struct {
		err error
		dir string
	}
	results := make(chan dirResult, 2)
	var wg sync.WaitGroup

	// Session wrappers: when NoClose*, cancel closes only the wrapper so a
	// shared end-close stream is not destroyed (classic EXECENDCLOSE).
	if cfg.NoCloseLeft {
		left = newSessionWrap(left)
	}
	if cfg.NoCloseRight {
		right = newSessionWrap(right)
	}

	// Unblock blocked Reads/Writes when the transfer is cancelled (UDP has no EOF).
	// Also poke read deadlines so stdin (FD 0) and other FDs unblock even when
	// Close is a no-op (STDIO).
	go func() {
		<-ctx.Done()
		pokeReadDeadline(left)
		pokeReadDeadline(right)
		_ = left.Close()
		_ = right.Close()
	}()

	copyDir := func(dst Stream, src Stream, dir string, bytes, blocks *atomic.Uint64) {
		defer wg.Done()
		bp := getBuf(cfg.BufferSize)
		defer putBuf(bp)
		buf := *bp
		if cap(buf) < cfg.BufferSize {
			buf = make([]byte, cfg.BufferSize)
		} else {
			buf = buf[:cfg.BufferSize]
		}

		// Classic backpressure: only read src when dst is writable.
		// Critical for STALL (full pipe never POLLOUT until closed).
		// Use direction-aware FDs: read side for src, write side for dst.
		dstFD := streamWriteFD(dst)
		srcFD := streamReadFD(src)
		usePoll := dstFD >= 0 && srcFD >= 0

		for {
			if ctx.Err() != nil {
				results <- dirResult{err: ctx.Err(), dir: dir}
				return
			}
			if usePoll {
				if err := waitReadableAndWritable(ctx, srcFD, dstFD); err != nil {
					results <- dirResult{err: err, dir: dir}
					return
				}
			}
			nr, er := src.Read(buf)
			if nr > 0 {
				touch()
				data := buf[:nr]
				if cfg.Verbose || cfg.Hex {
					dump(cfg, dir, data)
				}
				// Classic -r (left→right ">") / -R (right→left "<") raw dumps.
				if dir == ">" && cfg.RawLeft != nil {
					_, _ = cfg.RawLeft.Write(data)
				}
				if dir == "<" && cfg.RawRight != nil {
					_, _ = cfg.RawRight.Write(data)
				}
				nw, ew := dst.Write(data)
				if nw > 0 {
					bytes.Add(uint64(nw))
					blocks.Add(1)
				}
				if ew != nil {
					if isBenignClose(ew) {
						results <- dirResult{err: nil, dir: dir}
						return
					}
					results <- dirResult{err: ew, dir: dir}
					return
				}
				if nw != nr {
					results <- dirResult{err: io.ErrShortWrite, dir: dir}
					return
				}
			}
			if er != nil {
				if er == io.EOF || isBenignClose(er) {
					if cfg.OnEOF != nil {
						// dir ">": reading left (socket 1); dir "<": reading right (socket 2)
						sock := 1
						if dir == "<" {
							sock = 2
						}
						cfg.OnEOF(sock, streamReadFD(src))
					}
					_ = dst.ShutdownWrite()
					results <- dirResult{err: nil, dir: dir}
					return
				}
				results <- dirResult{err: er, dir: dir}
				return
			}
		}
	}

	nDirs := 0
	if cfg.LeftToRight {
		nDirs++
		wg.Add(1)
		go copyDir(right, left, ">", &tr.BytesLR, &tr.BlocksLR)
	}
	if cfg.RightToLeft {
		nDirs++
		wg.Add(1)
		go copyDir(left, right, "<", &tr.BytesRL, &tr.BlocksRL)
	}

	// Wait for first direction to finish; then linger for the other.
	var firstErr error
	finished := 0
	var lingerTimer *time.Timer
	var lingerC <-chan time.Time

	for finished < nDirs {
		select {
		case r := <-results:
			finished++
			if r.err != nil && r.err != context.Canceled && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", r.dir, r.err)
			}
			if finished == 1 && nDirs == 2 && cfg.Linger > 0 {
				lingerTimer = time.NewTimer(cfg.Linger)
				lingerC = lingerTimer.C
			} else if finished == 1 && nDirs == 2 && cfg.Linger == 0 {
				cancel()
			}
		case <-lingerC:
			cancel()
			// drain remaining
			for finished < nDirs {
				<-results
				finished++
			}
		case <-ctx.Done():
			for finished < nDirs {
				<-results
				finished++
			}
		}
	}
	if lingerTimer != nil {
		lingerTimer.Stop()
	}
	wg.Wait()

	st := tr.Snapshot()
	st.Duration = time.Since(start)
	if cfg.OnStats != nil {
		cfg.OnStats(st)
	}
	return firstErr
}

func dump(cfg Config, dir string, data []byte) {
	if cfg.Dump == nil {
		return
	}
	prefix := dir + " "
	if cfg.Hex {
		_, _ = fmt.Fprintf(cfg.Dump, "%s", prefix)
		for i, b := range data {
			if i > 0 {
				_, _ = fmt.Fprint(cfg.Dump, " ")
			}
			_, _ = fmt.Fprintf(cfg.Dump, "%02x", b)
		}
		_, _ = fmt.Fprintln(cfg.Dump)
		return
	}
	// text mode with simple escapes
	_, _ = fmt.Fprint(cfg.Dump, prefix)
	for _, b := range data {
		switch {
		case b == '\n':
			_, _ = fmt.Fprint(cfg.Dump, "\\n")
		case b == '\r':
			_, _ = fmt.Fprint(cfg.Dump, "\\r")
		case b == '\t':
			_, _ = fmt.Fprint(cfg.Dump, "\\t")
		case b < 32 || b >= 127:
			_, _ = fmt.Fprintf(cfg.Dump, "\\x%02x", b)
		default:
			_, _ = fmt.Fprint(cfg.Dump, string(b))
		}
	}
	_, _ = fmt.Fprintln(cfg.Dump)
}

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
	// Do not rely on SetReadDeadline: PTY masters (and some other FDs) ignore
	// deadlines while a slave/peer stays open, which hung PTYENDCLOSE forever.
	// Poll the underlying FD with a short timeout so Close can always stop us.
	fd := streamReadFD(s.inner)
	for {
		select {
		case <-s.done:
			return 0, io.EOF
		default:
		}
		if fd >= 0 {
			pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} // #nosec G115 -- conversion matches kernel or protocol width; value is range-checked or ABI-defined
			n, err := unix.Poll(pfd, 50)                               // 50ms
			if err != nil && err != syscall.EINTR {
				return 0, err
			}
			select {
			case <-s.done:
				return 0, io.EOF
			default:
			}
			if n == 0 {
				continue
			}
			// HUP/ERR with no data → let Read return EOF/error.
		} else {
			// No FD: fall back to short deadline if the stream supports it.
			setStreamReadDeadline(s.inner, time.Now().Add(50*time.Millisecond))
		}
		nr, err := s.inner.Read(p)
		if fd < 0 {
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
	select {
	case <-s.done:
		return 0, io.ErrClosedPipe
	default:
	}
	return s.inner.Write(p)
}

func (s *sessionWrap) Close() error {
	s.once.Do(func() {
		close(s.done)
		// Wake a blocked poll-Read without permanently poisoning the shared FD.
		setStreamReadDeadline(s.inner, time.Now().Add(time.Millisecond))
		go func() {
			time.Sleep(20 * time.Millisecond)
			setStreamReadDeadline(s.inner, time.Time{})
		}()
	})
	return nil
}

func (s *sessionWrap) ShutdownWrite() error {
	// NoCloseLeft/Right: do not half-close the shared underlying stream
	// (classic EXEC,end-close + LISTEN,fork keeps cat stdin open across accepts).
	return nil
}

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
		if f, ok := fs.R.(*os.File); ok {
			_ = f.SetReadDeadline(deadline)
		}
	}
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout")
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
		if f, ok := t.R.(*os.File); ok {
			set(f)
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
	if err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed {
		return true
	}
	if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file already closed") ||
		strings.Contains(msg, "use of closed") ||
		strings.Contains(msg, "broken pipe")
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
			if rs, ok := any(fs.R).(Stream); ok {
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
			if ws, ok := any(fs.W).(Stream); ok {
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

// waitReadableAndWritable waits until src is readable and dst is writable
// (classic select backpressure). If dst is closed/errored without being writable,
// return an error without reading (preserve unread peer data — needed for STALL).
func waitReadableAndWritable(ctx context.Context, srcFD, dstFD int) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pfd := []unix.PollFd{
			{Fd: int32(srcFD), Events: unix.POLLIN},  // #nosec G115 -- conversion matches kernel or protocol width; value is range-checked or ABI-defined
			{Fd: int32(dstFD), Events: unix.POLLOUT}, // #nosec G115 -- conversion matches kernel or protocol width; value is range-checked or ABI-defined
		}
		n, err := unix.Poll(pfd, 100) // 100ms so we honour ctx
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		srcRe := pfd[0].Revents
		dstRe := pfd[1].Revents
		// Destination dead and not writable: abort without consuming src.
		if dstRe&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 && dstRe&unix.POLLOUT == 0 {
			return io.ErrClosedPipe
		}
		// Source closed: allow Read to return EOF.
		if srcRe&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 && srcRe&unix.POLLIN == 0 {
			return nil
		}
		srcReady := srcRe&unix.POLLIN != 0
		dstReady := dstRe&unix.POLLOUT != 0
		if srcReady && dstReady {
			return nil
		}
	}
}
