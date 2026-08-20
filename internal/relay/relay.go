// Package relay implements bidirectional data transfer between two streams.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 8192)
		return &b
	},
}

// Avoid pinning one-off user-selected buffers as large as 256 MiB in the
// process-wide pool. Typical and moderately enlarged relay buffers still reuse
// allocations; exceptionally large buffers are released after the transfer.
const maxPooledBufferSize = 256 << 10

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

func shouldPoolBuffer(capacity int) bool {
	return capacity <= maxPooledBufferSize
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

	touch := startIdleWatch(ctx, cancel, cfg.IdleTimeout)

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

	// Resolve poll descriptors before cancellation can close either stream.
	// os.File permits concurrent I/O and Close, but Fd itself must not race
	// with Close. Keep the integer values for the lifetime of this transfer.
	lrDstFD, lrSrcFD := -1, -1
	rlDstFD, rlSrcFD := -1, -1
	var lrZeroCopy, rlZeroCopy zeroCopyPlan
	// Ordinary net.Conn and regular-file I/O already gets blocking readiness
	// from Go and the kernel. Polling before every block only adds a syscall.
	// Keep explicit poll backpressure for non-regular descriptors (pipes,
	// terminals) and custom raw-FD streams such as TUN and generic SOCKET.
	useExplicitPoll := canPoll() && (streamNeedsExplicitPoll(left) || streamNeedsExplicitPoll(right))
	if useExplicitPoll {
		if cfg.LeftToRight {
			lrDstFD = streamWriteFD(right)
			lrSrcFD = streamReadFD(left)
		}
		if cfg.RightToLeft {
			rlDstFD = streamWriteFD(left)
			rlSrcFD = streamReadFD(right)
		}
	}
	// Prepare kernel-copy descriptors while the original streams are known to
	// be open. Unsupported platforms and endpoint pairs return nil and retain
	// the ordinary configured-buffer path.
	if cfg.LeftToRight && canZeroCopy(cfg, ">", useExplicitPoll) {
		lrZeroCopy = prepareZeroCopy(left, right)
	}
	if cfg.RightToLeft && canZeroCopy(cfg, "<", useExplicitPoll) {
		rlZeroCopy = prepareZeroCopy(right, left)
	}

	// Close and ShutdownWrite may both be triggered during cancellation. They
	// must not operate on the same descriptor concurrently, while Read/Write
	// remain unlocked so Close can still interrupt blocked I/O.
	left = newCloseSerialStream(left)
	right = newCloseSerialStream(right)

	// Unblock blocked Reads/Writes when the transfer is cancelled (UDP has no EOF).
	// Also poke read deadlines so stdin (FD 0) and other FDs unblock even when
	// Close is a no-op (STDIO).
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		<-ctx.Done()
		pokeReadDeadline(left)
		pokeReadDeadline(right)
		_ = left.Close()
		_ = right.Close()
	}()

	nDirs := 0
	if cfg.LeftToRight {
		nDirs++
		wg.Add(1)
		go copyDir(ctx, right, left, ">", lrDstFD, lrSrcFD, lrZeroCopy, &tr.BytesLR, &tr.BlocksLR, cfg, touch, results, &wg)
	}
	if cfg.RightToLeft {
		nDirs++
		wg.Add(1)
		go copyDir(ctx, left, right, "<", rlDstFD, rlSrcFD, rlZeroCopy, &tr.BytesRL, &tr.BlocksRL, cfg, touch, results, &wg)
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
	cancel()
	<-closeDone

	st := tr.Snapshot()
	st.Duration = time.Since(start)
	if cfg.OnStats != nil {
		cfg.OnStats(st)
	}
	return firstErr
}

type dirResult struct {
	err error
	dir string
}

func startIdleWatch(ctx context.Context, cancel context.CancelFunc, idle time.Duration) func() {
	if idle <= 0 {
		return func() {}
	}
	var mu sync.Mutex
	last := time.Now()
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				since := time.Since(last)
				mu.Unlock()
				if since >= idle {
					cancel()
					return
				}
			}
		}
	}()
	return func() {
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}
}

func copyDir(ctx context.Context, dst, src Stream, dir string, dstFD, srcFD int, zeroCopy zeroCopyPlan, bytes, blocks *atomic.Uint64, cfg Config, touch func(), results chan<- dirResult, wg *sync.WaitGroup) {
	defer wg.Done()
	if zeroCopy != nil {
		defer func() { _ = zeroCopy.Close() }()
		onRead := func(n int64) {
			if n <= 0 {
				return
			}
			touch()
			blockSize := int64(cfg.BufferSize)
			blocks.Add(uint64((n + blockSize - 1) / blockSize))
		}
		onWrite := func(n int64) {
			if n > 0 {
				bytes.Add(uint64(n))
			}
		}
		err := zeroCopy.Copy(ctx, onRead, onWrite)
		if !errors.Is(err, errZeroCopyUnsupported) {
			if err == nil {
				if cfg.OnEOF != nil {
					sock := 1
					if dir == "<" {
						sock = 2
					}
					cfg.OnEOF(sock, srcFD)
				}
				if ctx.Err() == nil {
					_ = dst.ShutdownWrite()
				}
				results <- dirResult{err: nil, dir: dir}
				return
			}
			// A benign destination close is a clean transfer termination, but
			// it is not evidence that the source reached EOF.
			if isBenignClose(err) {
				results <- dirResult{err: nil, dir: dir}
				return
			}
			results <- dirResult{err: err, dir: dir}
			return
		}
	}

	var bp *[]byte
	if shouldPoolBuffer(cfg.BufferSize) {
		bp = getBuf(cfg.BufferSize)
		defer putBuf(bp)
	} else {
		b := make([]byte, cfg.BufferSize)
		bp = &b
	}
	buf := *bp
	if cap(buf) < cfg.BufferSize {
		buf = make([]byte, cfg.BufferSize)
	} else {
		buf = buf[:cfg.BufferSize]
	}

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
				if err := dump(cfg, dir, data); err != nil {
					results <- dirResult{err: fmt.Errorf("verbose dump: %w", err), dir: dir}
					return
				}
			}
			if dir == ">" && cfg.RawLeft != nil {
				if err := writeDump(cfg.RawLeft, data); err != nil {
					results <- dirResult{err: fmt.Errorf("raw left dump: %w", err), dir: dir}
					return
				}
			}
			if dir == "<" && cfg.RawRight != nil {
				if err := writeDump(cfg.RawRight, data); err != nil {
					results <- dirResult{err: fmt.Errorf("raw right dump: %w", err), dir: dir}
					return
				}
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
					sock := 1
					if dir == "<" {
						sock = 2
					}
					cfg.OnEOF(sock, srcFD)
				}
				if ctx.Err() == nil {
					_ = dst.ShutdownWrite()
				}
				results <- dirResult{err: nil, dir: dir}
				return
			}
			results <- dirResult{err: er, dir: dir}
			return
		}
	}
}

func writeDump(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
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

func dump(cfg Config, dir string, data []byte) error {
	if cfg.Dump == nil {
		return nil
	}
	const maxDumpOutputBuffer = 256 << 10
	maxEncoded := 4 * len(data)
	if cfg.Hex {
		maxEncoded = 3 * len(data)
	}
	if len(dir)+2+maxEncoded > maxDumpOutputBuffer {
		return dumpLarge(cfg, dir, data)
	}
	out := make([]byte, 0, len(dir)+2+maxEncoded)
	out = append(out, dir...)
	out = append(out, ' ')
	const hexDigits = "0123456789abcdef"
	if cfg.Hex {
		for i, b := range data {
			if i > 0 {
				out = append(out, ' ')
			}
			out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
		}
		out = append(out, '\n')
		return writeDump(cfg.Dump, out)
	}
	// text mode with simple escapes
	for _, b := range data {
		switch {
		case b == '\n':
			out = append(out, '\\', 'n')
		case b == '\r':
			out = append(out, '\\', 'r')
		case b == '\t':
			out = append(out, '\\', 't')
		case b < 32 || b >= 127:
			out = append(out, '\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f])
		default:
			out = append(out, b)
		}
	}
	out = append(out, '\n')
	return writeDump(cfg.Dump, out)
}

// dumpLarge preserves the single-line dump format without allocating up to
// four times an arbitrarily large relay buffer. Normal 8 KiB dumps stay on the
// faster single-write path above.
func dumpLarge(cfg Config, dir string, data []byte) error {
	if err := writeDump(cfg.Dump, []byte(dir+" ")); err != nil {
		return err
	}
	const inputChunk = 64 << 10
	const hexDigits = "0123456789abcdef"
	for start := 0; start < len(data); start += inputChunk {
		end := min(start+inputChunk, len(data))
		chunk := data[start:end]
		out := make([]byte, 0, 4*len(chunk))
		if cfg.Hex {
			for i, b := range chunk {
				if start+i > 0 {
					out = append(out, ' ')
				}
				out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
			}
		} else {
			for _, b := range chunk {
				switch {
				case b == '\n':
					out = append(out, '\\', 'n')
				case b == '\r':
					out = append(out, '\\', 'r')
				case b == '\t':
					out = append(out, '\\', 't')
				case b < 32 || b >= 127:
					out = append(out, '\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f])
				default:
					out = append(out, b)
				}
			}
		}
		if err := writeDump(cfg.Dump, out); err != nil {
			return err
		}
	}
	return writeDump(cfg.Dump, []byte{'\n'})
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

// canZeroCopy reports whether a unidirectional stream transfer is eligible
// for zero-copy kernel splicing / sendfile.
func canZeroCopy(cfg Config, dir string, usePoll bool) bool {
	if cfg.Verbose || cfg.Hex || usePoll {
		return false
	}
	if dir == ">" && cfg.RawLeft != nil {
		return false
	}
	if dir == "<" && cfg.RawRight != nil {
		return false
	}
	return true
}

func unwrapZeroCopyReader(s io.Reader) (io.Reader, bool) {
	for i := 0; i < 8 && s != nil; i++ {
		if u, ok := s.(interface{ UnwrapZeroCopyStream() Stream }); ok {
			s = u.UnwrapZeroCopyStream()
			continue
		}
		if fs, ok := s.(FDStream); ok {
			s = fs.R
			continue
		}
		if ns, ok := s.(NetStream); ok {
			s = ns.Conn
			continue
		}
		break
	}
	switch v := s.(type) {
	case *net.TCPConn, *net.UnixConn, *os.File:
		return v, true
	default:
		return nil, false
	}
}

func unwrapZeroCopyWriter(s io.Writer) (io.Writer, bool) {
	for i := 0; i < 8 && s != nil; i++ {
		if u, ok := s.(interface{ UnwrapZeroCopyStream() Stream }); ok {
			s = u.UnwrapZeroCopyStream()
			continue
		}
		if fs, ok := s.(FDStream); ok {
			s = fs.W
			continue
		}
		if ns, ok := s.(NetStream); ok {
			s = ns.Conn
			continue
		}
		break
	}
	switch v := s.(type) {
	case *net.TCPConn, *net.UnixConn, *os.File:
		return v, true
	default:
		return nil, false
	}
}
