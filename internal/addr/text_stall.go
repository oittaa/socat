package addr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// TEXT:<string> — input is the string (with classic escapes); output goes to stdout.
func openTEXT(_ context.Context, s parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("TEXT requires string parameter")
	}
	// TEXT::::: probe → empty params; still require non-empty content
	if len(s.Params) == 1 && s.Params[0] == "" {
		return nil, fmt.Errorf("TEXT requires string parameter")
	}
	// Escapes already expanded by the address parser (quotes / backslash).
	raw := strings.Join(s.Params, ":")
	data := []byte(raw)
	r := bytes.NewReader(data)
	var stream relay.Stream
	switch mode {
	case ModeRead:
		stream = relay.FDStream{R: r, W: discardWriter{}, C: nopCloser{}}
	case ModeWrite:
		stream = relay.FDStream{R: eofReader{}, W: os.Stdout, C: nopCloser{}}
	default:
		stream = relay.FDStream{
			R: r,
			W: os.Stdout,
			C: nopCloser{},
		}
	}
	st, err := wrapCommon(s, stream)
	if err != nil {
		return nil, err
	}
	return &Opened{Stream: st, Label: "TEXT"}, nil
}

// STALL — never readable, never writable (classic: pipes that never become ready).
//
// Classic fills the write-end pipe to capacity so poll/select never marks it
// writable; that prevents the transfer loop from reading the peer (backpressure).
// Read side is a pipe whose write end is never written, so it never becomes readable.
// Closing the FDs (idle -T, process exit) unblocks I/O.
func openSTALL(_ context.Context, s parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	// Classic STALL takes no parameters. testaddrs probes with STALL::::: and
	// expects a parse/syntax failure so the process does not hang transferring.
	if len(s.Params) > 0 {
		return nil, fmt.Errorf("STALL: wrong number of parameters (expected 0)")
	}
	var r io.Reader = eofReader{}
	var w io.Writer = discardWriter{}
	var cleanup []func()
	var closeFDs []int

	// Read stall: pipe with only read end held open; never has data.
	if mode == ModeRead || mode == ModeRDWR {
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		// Keep write end open so Read blocks (not EOF); drop after process ends.
		r = pr
		closeFDs = append(closeFDs, int(pr.Fd()), int(pw.Fd()))
		cleanup = append(cleanup, func() {
			pr.Close()
			pw.Close()
		})
	}

	// Write stall: pipe filled to capacity so further Writes block.
	if mode == ModeWrite || mode == ModeRDWR {
		pr, pw, err := os.Pipe()
		if err != nil {
			for _, f := range cleanup {
				f()
			}
			return nil, err
		}
		// Keep read end open; fill write end.
		fillPipe(pw)
		w = pw
		closeFDs = append(closeFDs, int(pr.Fd()), int(pw.Fd()))
		cleanup = append(cleanup, func() {
			pr.Close()
			pw.Close()
		})
	}

	stream := relay.FDStream{
		R: r,
		W: w,
		C: multiCloserFuncs(cleanup),
		CloseW: func() error {
			// Closing write end of write-stall pipe unblocks any blocked Write.
			if c, ok := w.(io.Closer); ok {
				return c.Close()
			}
			return nil
		},
	}
	// When idle timeout cancels, Close() runs cleanup and unblocks.
	_ = closeFDs
	return &Opened{Stream: stream, Label: "STALL"}, nil
}

// fillPipe writes zeros until the pipe buffer is full (classic STALL write side).
func fillPipe(pw *os.File) {
	// Prefer F_GETPIPE_SZ when available.
	sz := 65536
	if n, err := unix.FcntlInt(pw.Fd(), unix.F_GETPIPE_SZ, 0); err == nil && n > 0 {
		sz = n
	}
	// Non-blocking fill
	raw, err := pw.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		flags, _ := unix.FcntlInt(fd, unix.F_GETFL, 0)
		_, _ = unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NONBLOCK)
		zeros := make([]byte, sz)
		for {
			n, err := unix.Write(int(fd), zeros)
			if n < 0 || err != nil {
				break
			}
			if n < len(zeros) {
				break
			}
		}
		_, _ = unix.FcntlInt(fd, unix.F_SETFL, flags)
	})
}

type multiCloserFuncs []func()

func (m multiCloserFuncs) Close() error {
	for i := len(m) - 1; i >= 0; i-- {
		m[i]()
	}
	return nil
}

// expandEscapes handles common classic socat string escapes.
func expandEscapes(s string) []byte {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '0':
			b.WriteByte(0)
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				var v byte
				fmt.Sscanf(s[i+1:i+3], "%02x", &v)
				b.WriteByte(v)
				i += 2
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return []byte(b.String())
}

// silence
var _ = syscall.O_NONBLOCK
