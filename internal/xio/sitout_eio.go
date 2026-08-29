//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// SitoutEIO is PTY sitout-eio. Omitted or 0: EIO on the PTY master is EOF
// (login closed the slave). Positive timeval: poll 10ms loops for
// 100*sec + ceil(usec/10000) ticks, then return the EIO. The last tick
// sleeps without another Read.
func SitoutEIO(s parse.Spec) (time.Duration, error) {
	if !s.HasOption("sitout-eio") {
		return 0, nil
	}
	o, _ := s.OptionNamed("sitout-eio")
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, fmt.Errorf("sitout-eio: option requires a value")
	}
	d, err := parseTimeval(o.Value)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("sitout-eio: invalid timeval %q", o.Value)
	}
	return d, nil
}

func wrapSitoutEIORead(r io.Reader, d time.Duration) io.Reader {
	return &sitoutEIOReader{r: r, d: d}
}

type sitoutEIOReader struct {
	r io.Reader
	d time.Duration
}

func sitoutEIOTicks(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	usec := d.Microseconds()
	return int((usec + 9999) / 10000)
}

func (s *sitoutEIOReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 || err == nil {
		return n, err
	}
	if !errors.Is(err, syscall.EIO) {
		return n, err
	}
	ticks := sitoutEIOTicks(s.d)
	if ticks == 0 {
		return 0, io.EOF
	}
	remaining := ticks
	for {
		time.Sleep(10 * time.Millisecond)
		remaining--
		if remaining <= 0 {
			return 0, err
		}
		n, err = s.r.Read(p)
		if n > 0 || err == nil {
			return n, err
		}
		if !errors.Is(err, syscall.EIO) {
			return n, err
		}
	}
}

func (s *sitoutEIOReader) Fd() uintptr {
	if f, ok := s.r.(interface{ Fd() uintptr }); ok {
		return f.Fd()
	}
	return ^uintptr(0)
}

func (s *sitoutEIOReader) SyscallConn() (syscall.RawConn, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if c, ok := s.r.(syscallConner); ok {
		return c.SyscallConn()
	}
	return nil, os.ErrInvalid
}
