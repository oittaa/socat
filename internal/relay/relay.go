// Package relay implements bidirectional data transfer between two streams.
package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
	// OnStats is called with final counters if non-nil.
	OnStats func(Stats)
}

// Stats holds transfer counters.
type Stats struct {
	BytesLR   uint64
	BytesRL   uint64
	BlocksLR  uint64
	BlocksRL  uint64
	Duration  time.Duration
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
	R         io.Reader
	W         io.Writer
	C         io.Closer
	CloseW    func() error
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
	var bytesLR, bytesRL, blocksLR, blocksRL atomic.Uint64

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

	// Unblock blocked Reads/Writes when the transfer is cancelled (UDP has no EOF).
	go func() {
		<-ctx.Done()
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

		for {
			if ctx.Err() != nil {
				results <- dirResult{err: ctx.Err(), dir: dir}
				return
			}
			nr, er := src.Read(buf)
			if nr > 0 {
				touch()
				data := buf[:nr]
				if cfg.Verbose || cfg.Hex {
					dump(cfg, dir, data)
				}
				nw, ew := dst.Write(data)
				if nw > 0 {
					bytes.Add(uint64(nw))
					blocks.Add(1)
				}
				if ew != nil {
					results <- dirResult{err: ew, dir: dir}
					return
				}
				if nw != nr {
					results <- dirResult{err: io.ErrShortWrite, dir: dir}
					return
				}
			}
			if er != nil {
				if er == io.EOF {
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
		go copyDir(right, left, ">", &bytesLR, &blocksLR)
	}
	if cfg.RightToLeft {
		nDirs++
		wg.Add(1)
		go copyDir(left, right, "<", &bytesRL, &blocksRL)
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

	st := Stats{
		BytesLR:  bytesLR.Load(),
		BytesRL:  bytesRL.Load(),
		BlocksLR: blocksLR.Load(),
		BlocksRL: blocksRL.Load(),
		Duration: time.Since(start),
	}
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
		fmt.Fprintf(cfg.Dump, "%s", prefix)
		for i, b := range data {
			if i > 0 {
				fmt.Fprint(cfg.Dump, " ")
			}
			fmt.Fprintf(cfg.Dump, "%02x", b)
		}
		fmt.Fprintln(cfg.Dump)
		return
	}
	// text mode with simple escapes
	fmt.Fprint(cfg.Dump, prefix)
	for _, b := range data {
		switch {
		case b == '\n':
			fmt.Fprint(cfg.Dump, "\\n")
		case b == '\r':
			fmt.Fprint(cfg.Dump, "\\r")
		case b == '\t':
			fmt.Fprint(cfg.Dump, "\\t")
		case b < 32 || b >= 127:
			fmt.Fprintf(cfg.Dump, "\\x%02x", b)
		default:
			fmt.Fprint(cfg.Dump, string(b))
		}
	}
	fmt.Fprintln(cfg.Dump)
}
