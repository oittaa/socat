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

// DefaultLinger is the -t default: how long the second direction may
// keep flushing after the first side EOFs (0.5s).
const DefaultLinger = 500 * time.Millisecond

const idleWatchInterval = 100 * time.Millisecond

// Config controls transfer behavior.
type Config struct {
	// BufferSize is the max bytes per read (-b, default 8192).
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
	// RawLeft/RawRight: -r / -R binary dumps of transferred data.
	RawLeft  io.Writer // left→right
	RawRight io.Writer // right→left
	// Tracker receives live counters (SIGUSR1 / --statistics). If nil, Transfer
	// allocates one and registers it.
	Tracker *Tracker
	// OnStats is called with final counters if non-nil.
	OnStats func(Stats)
	// OnEOF is called once per direction when that side reaches EOF
	// (MULTIPLE_EOF: "socket N (fd X) is at EOF"). sock is 1=left, 2=right.
	OnEOF func(sock int, fd int)
	// NoCloseLeft/Right: on cancel, do not Close that stream (end-close
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

// direction is one copy of a bidirectional transfer.
type direction uint8

const (
	dirLeftToRight direction = iota + 1 // ">"
	dirRightToLeft                      // "<"
)

func (d direction) String() string {
	switch d {
	case dirLeftToRight:
		return ">"
	case dirRightToLeft:
		return "<"
	default:
		return "?"
	}
}

// sock is the classic MULTIPLE_EOF socket number: 1=left, 2=right.
func (d direction) sock() int {
	switch d {
	case dirLeftToRight:
		return 1
	case dirRightToLeft:
		return 2
	default:
		return 0
	}
}

// dirClass is decided once when a direction finishes. Transfer does not
// reclassify from the raw error.
type dirClass uint8

const (
	classOK       dirClass = iota // clean EOF or benign close
	classCanceled                 // exact context.Canceled
	classFailed                   // any other error, including wrapped Canceled
)

// dirOutcome is the classified result of one direction.
type dirOutcome struct {
	dir   direction
	class dirClass
	err   error
}

func classifyDirError(dir direction, err error) dirOutcome {
	o := dirOutcome{dir: dir, err: err}
	switch err {
	case nil:
		o.class = classOK
	case context.Canceled:
		o.class = classCanceled
	default:
		o.class = classFailed
	}
	return o
}

// transferOutcomes is owned by Transfer: both direction slots, plus the
// live results that publish() may select after cleanup.
type transferOutcomes struct {
	leftToRight dirOutcome
	rightToLeft dirOutcome
	live        []dirOutcome
}

func (o *transferOutcomes) store(r dirOutcome) {
	switch r.dir {
	case dirLeftToRight:
		o.leftToRight = r
	case dirRightToLeft:
		o.rightToLeft = r
	}
}

func (o *transferOutcomes) keep(r dirOutcome) {
	o.store(r)
	if r.dir == dirLeftToRight || r.dir == dirRightToLeft {
		o.live = append(o.live, r)
	}
}

func (o *transferOutcomes) drain(r dirOutcome) {
	o.store(r)
}

func (o transferOutcomes) publish() error {
	var first error
	for _, r := range o.live {
		first = selectTransferError(first, r)
	}
	return first
}

// Transfer error-selection rules (preserve these; do not "improve"):
//
// Direction result (copyDir):
//   - Clean source EOF and benign source close become a nil error. Those
//     paths also call OnEOF and ShutdownWrite when the transfer context
//     is still active.
//   - Benign destination close (zero-copy, poll, or write) is also nil,
//     but is not source EOF: no OnEOF.
//   - context.Err() at the start of a read loop is returned as-is
//     (typically context.Canceled after linger, idle, or parent cancel).
//   - Dump/write/read failures and non-benign poll errors are returned
//     as-is, except verbose/raw dump errors which are wrapped with a
//     fixed prefix.
//
// Combining the two directions (Transfer):
//   - Transfer owns both classified dirOutcome values, cancel, linger,
//     stats, and write-side shutdown.
//   - The wait loop only stores results and marks them live or drained.
//     Results drained after linger expiry or parent ctx.Done() are stored
//     and must not change the selected error.
//   - publish() runs after Wait, cancel, close, and OnStats. It walks
//     live classified outcomes only.
//   - classOK (nil) is not a transfer error.
//   - classCanceled (exact context.Canceled, identity, not errors.Is)
//     is ignored. Wrapped Canceled and context.DeadlineExceeded are
//     classFailed and are transfer errors.
//   - The first remaining classFailed wins; later errors are discarded.
//   - The selected error is wrapped as "<dir>: <err>" where dir is ">"
//     (left→right) or "<" (right→left).
//   - Linger expiry and idle timeout only cancel the context. They do
//     not invent an error. If every live result is classOK or
//     classCanceled, Transfer returns nil.
func selectTransferError(first error, o dirOutcome) error {
	if first != nil || o.class != classFailed {
		return first
	}
	return fmt.Errorf("%s: %w", o.dir.String(), o.err)
}

// Transfer copies data bidirectionally between left and right until both
// directions finish. It owns both classified outcomes, cancel, linger,
// stats, and write-side shutdown. The transfer result is published after
// that cleanup. It does not use io.Copy.
func Transfer(ctx context.Context, left, right Stream, cfg Config) error {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 8192
	}
	if !cfg.LeftToRight && !cfg.RightToLeft {
		cfg.LeftToRight = true
		cfg.RightToLeft = true
	}
	if cfg.Linger < 0 {
		cfg.Linger = DefaultLinger
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

	touch, stopIdle := startIdleWatch(ctx, cancel, cfg.IdleTimeout)
	defer stopIdle()

	results := make(chan dirOutcome, 2)
	var wg sync.WaitGroup
	var outcomes transferOutcomes

	// Session wrappers: when NoClose*, cancel closes only the wrapper so a
	// shared end-close stream is not destroyed (EXECENDCLOSE).
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
	if cfg.LeftToRight && zeroCopyAllowed(cfg, dirLeftToRight, useExplicitPoll) {
		lrZeroCopy = prepareZeroCopy(left, right)
	}
	if cfg.RightToLeft && zeroCopyAllowed(cfg, dirRightToLeft, useExplicitPoll) {
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
		go copyDir(ctx, dirTask{dir: dirLeftToRight, dst: right, src: left, dstFD: lrDstFD, srcFD: lrSrcFD, plan: lrZeroCopy, bytes: &tr.BytesLR, blocks: &tr.BlocksLR}, cfg, touch, results, &wg)
	}
	if cfg.RightToLeft {
		nDirs++
		wg.Add(1)
		go copyDir(ctx, dirTask{dir: dirRightToLeft, dst: left, src: right, dstFD: rlDstFD, srcFD: rlSrcFD, plan: rlZeroCopy, bytes: &tr.BytesRL, blocks: &tr.BlocksRL}, cfg, touch, results, &wg)
	}

	// Wait for first direction to finish; then linger for the other.
	finished := 0
	var lingerTimer *time.Timer
	var lingerC <-chan time.Time

	for finished < nDirs {
		select {
		case r := <-results:
			finished++
			outcomes.keep(r)
			if finished == 1 && nDirs == 2 && cfg.Linger > 0 {
				// After one side EOFs, -t owns the rest of the session.
				// -T is inactivity while both directions still run.
				stopIdle()
				lingerTimer = time.NewTimer(cfg.Linger)
				lingerC = lingerTimer.C
			} else if finished == 1 && nDirs == 2 && cfg.Linger == 0 {
				cancel()
			}
		case <-lingerC:
			cancel()
			// Drain remaining: store the outcome, do not inspect it.
			for finished < nDirs {
				outcomes.drain(<-results)
				finished++
			}
		case <-ctx.Done():
			for finished < nDirs {
				outcomes.drain(<-results)
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
	return outcomes.publish()
}

func startIdleWatch(ctx context.Context, cancel context.CancelFunc, idle time.Duration) (touch, stop func()) {
	nop := func() {}
	if idle <= 0 {
		return nop, nop
	}
	started := time.Now()
	var lastActivity atomic.Int64
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	clock := processIdleClock.subscribe()
	go func() {
		defer clock.close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-clock.next():
				elapsed := time.Since(started)
				last := time.Duration(lastActivity.Load())
				if elapsed-last >= idle {
					// Do not expire progress that raced with this tick.
					if current := lastActivity.Load(); current != int64(last) {
						continue
					}
					cancel()
					return
				}
			}
		}
	}()
	touch = func() {
		now := int64(time.Since(started))
		for {
			last := lastActivity.Load()
			if now <= last || lastActivity.CompareAndSwap(last, now) {
				return
			}
		}
	}
	return touch, stop
}

// dirTask bundles one transfer direction: source and destination streams, the
// descriptors captured for poll backpressure, an optional zero-copy plan, and
// the direction's live counters.
type dirTask struct {
	dir      direction
	dst, src Stream
	dstFD    int
	srcFD    int
	plan     zeroCopyPlan
	bytes    *atomic.Uint64
	blocks   *atomic.Uint64
}

func (t dirTask) send(results chan<- dirOutcome, err error) {
	results <- classifyDirError(t.dir, err)
}

func reportEOF(cfg Config, d direction, fd int) {
	if cfg.OnEOF != nil {
		cfg.OnEOF(d.sock(), fd)
	}
}

func copyDir(ctx context.Context, t dirTask, cfg Config, touch func(), results chan<- dirOutcome, wg *sync.WaitGroup) {
	defer wg.Done()
	if t.plan != nil {
		defer func() { _ = t.plan.Close() }()
		onRead := func(n int64) {
			if n <= 0 {
				return
			}
			touch()
			t.blocks.Add(configuredBlockCount(n, cfg.BufferSize))
		}
		onWrite := func(n int64) {
			if n > 0 {
				t.bytes.Add(uint64(n))
			}
		}
		err := t.plan.Copy(ctx, onRead, onWrite)
		if !errors.Is(err, errZeroCopyUnsupported) {
			if err == nil {
				reportEOF(cfg, t.dir, t.srcFD)
				if ctx.Err() == nil {
					_ = t.dst.ShutdownWrite()
				}
				t.send(results, nil)
				return
			}
			// A benign destination close is a clean transfer termination, but
			// it is not evidence that the source reached EOF.
			if isBenignClose(err) {
				t.send(results, nil)
				return
			}
			t.send(results, err)
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

	usePoll := t.dstFD >= 0 && t.srcFD >= 0

	for {
		if ctx.Err() != nil {
			t.send(results, ctx.Err())
			return
		}
		if usePoll {
			if err := waitReadableAndWritable(ctx, t.srcFD, t.dstFD); err != nil {
				// macOS socketpair/pipe HUP often arrives without POLLOUT, so
				// poll returns ErrClosedPipe before Read. That is the same
				// peer-gone case isBenignClose already accepts on Write.
				if isBenignClose(err) {
					t.send(results, nil)
					return
				}
				t.send(results, err)
				return
			}
		}
		nr, er := t.src.Read(buf)
		if nr > 0 {
			touch()
			data := buf[:nr]
			if cfg.Verbose || cfg.Hex {
				if err := dump(cfg, t.dir.String(), data); err != nil {
					t.send(results, fmt.Errorf("verbose dump: %w", err))
					return
				}
			}
			if t.dir == dirLeftToRight && cfg.RawLeft != nil {
				if err := writeDump(cfg.RawLeft, data); err != nil {
					t.send(results, fmt.Errorf("raw left dump: %w", err))
					return
				}
			}
			if t.dir == dirRightToLeft && cfg.RawRight != nil {
				if err := writeDump(cfg.RawRight, data); err != nil {
					t.send(results, fmt.Errorf("raw right dump: %w", err))
					return
				}
			}
			wroteBlock, ew := writeBlock(ctx, t.dst, t.dstFD, data, t.bytes)
			if wroteBlock {
				t.blocks.Add(1)
			}
			if ew != nil {
				if isBenignClose(ew) {
					t.send(results, nil)
					return
				}
				t.send(results, ew)
				return
			}
		}
		if er != nil {
			if isRetryableIOError(er) {
				continue
			}
			if er == io.EOF || isBenignClose(er) {
				reportEOF(cfg, t.dir, t.srcFD)
				if ctx.Err() == nil {
					_ = t.dst.ShutdownWrite()
				}
				t.send(results, nil)
				return
			}
			t.send(results, er)
			return
		}
	}
}

// writeBlock preserves partial progress across retryable send errors.
// The block count is owned by the caller and advances once when any
// bytes from this source read were written, rather than once per retry.
func writeBlock(ctx context.Context, dst Stream, dstFD int, data []byte, bytes *atomic.Uint64) (bool, error) {
	written := 0
	wroteBlock := false
	for written < len(data) {
		if err := ctx.Err(); err != nil {
			return wroteBlock, err
		}
		nw, err := dst.Write(data[written:])
		remaining := len(data) - written
		if nw < 0 || nw > remaining {
			return wroteBlock, fmt.Errorf("invalid write count %d", nw)
		}
		if nw > 0 {
			written += nw
			bytes.Add(uint64(nw))
			wroteBlock = true
		}
		if err != nil {
			if isRetryableIOError(err) {
				if dstFD >= 0 && isWouldBlock(err) {
					if waitErr := waitWritable(ctx, dstFD); waitErr != nil {
						return wroteBlock, waitErr
					}
				}
				continue
			}
			return wroteBlock, err
		}
		if nw == 0 {
			return wroteBlock, io.ErrNoProgress
		}
	}
	return wroteBlock, nil
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
	if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return isBenignPlatformClose(err)
}

func configuredBlockCount(n int64, bufferSize int) uint64 {
	if n <= 0 || bufferSize <= 0 {
		return 0
	}
	blockSize := int64(bufferSize)
	count := n / blockSize
	if n%blockSize != 0 {
		count++
	}
	if count < 0 {
		return 0
	}
	return uint64(count)
}
