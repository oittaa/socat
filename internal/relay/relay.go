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

// DefaultLinger is the classic -t default: how long the second direction may
// keep flushing after the first side EOFs (0.5s).
const DefaultLinger = 500 * time.Millisecond

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
	if cfg.LeftToRight && zeroCopyAllowed(cfg, ">", useExplicitPoll) {
		lrZeroCopy = prepareZeroCopy(left, right)
	}
	if cfg.RightToLeft && zeroCopyAllowed(cfg, "<", useExplicitPoll) {
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
			blocks.Add(configuredBlockCount(n, cfg.BufferSize))
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
