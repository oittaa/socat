package addr

import (
	"io"
	"time"
)

// ignoreEOFReader retries Read after EOF with a short sleep (classic ignoreeof).
// Stops when the underlying reader returns a non-EOF error or after maxIdle
// of continuous EOFs without data (safety bound).
type ignoreEOFReader struct {
	r       io.Reader
	idle    time.Duration
	maxIdle time.Duration
	waited  time.Duration
}

func newIgnoreEOF(r io.Reader) *ignoreEOFReader {
	return &ignoreEOFReader{
		r:       r,
		idle:    50 * time.Millisecond,
		maxIdle: 5 * time.Second,
	}
}

func (i *ignoreEOFReader) Read(p []byte) (int, error) {
	for {
		n, err := i.r.Read(p)
		if n > 0 {
			i.waited = 0
			return n, nil
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			return 0, err
		}
		// EOF: wait and retry
		i.waited += i.idle
		if i.waited >= i.maxIdle {
			return 0, io.EOF
		}
		time.Sleep(i.idle)
	}
}
