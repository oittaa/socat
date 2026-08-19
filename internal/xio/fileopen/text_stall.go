package fileopen

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// TEXT:<string> — input is the string (with classic escapes); output goes to stdout.
func openTEXT(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
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
	case xio.ModeRead:
		stream = relay.FDStream{R: r, W: io.Discard, C: xio.NopCloser{}}
	case xio.ModeWrite:
		stream = relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}}
	default:
		stream = relay.FDStream{
			R: r,
			W: os.Stdout,
			C: xio.NopCloser{},
		}
	}
	st, err := xio.WrapCommon(s, stream)
	if err != nil {
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "TEXT"}, nil
}

// STALL — never readable, never writable (classic: pipes that never become ready).
//
// Classic fills the write-end pipe to capacity so poll/select never marks it
// writable; that prevents the transfer loop from reading the peer (backpressure).
// xio.Read side is a pipe whose write end is never written, so it never becomes readable.
// Closing the FDs (idle -T, process exit) unblocks I/O.
func openSTALL(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if !xio.FeatureSTALL {
		return nil, fmt.Errorf("STALL is not supported on this platform")
	}
	// Classic STALL takes no parameters. testaddrs probes with STALL::::: and
	// expects a parse/syntax failure so the process does not hang transferring.
	if len(s.Params) > 0 {
		return nil, fmt.Errorf("STALL: wrong number of parameters (expected 0)")
	}
	var r io.Reader = xio.EOFReader{}
	var w = io.Discard
	var cleanup []func()
	var closeFDs []int

	// xio.Read stall: pipe with only read end held open; never has data.
	if mode == xio.ModeRead || mode == xio.ModeRDWR {
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		// Keep write end open so xio.Read blocks (not EOF); drop after process ends.
		r = pr
		closeFDs = append(closeFDs, int(pr.Fd()), int(pw.Fd()))
		cleanup = append(cleanup, func() {
			_ = pr.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			_ = pw.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		})
	}

	// xio.Write stall: pipe filled to capacity so further Writes block.
	if mode == xio.ModeWrite || mode == xio.ModeRDWR {
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
			_ = pr.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			_ = pw.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		})
	}

	stream := relay.FDStream{
		R: r,
		W: w,
		C: multiCloserFuncs(cleanup),
		CloseW: func() error {
			// Closing write end of write-stall pipe unblocks any blocked xio.Write.
			if c, ok := w.(io.Closer); ok {
				return c.Close()
			}
			return nil
		},
	}
	// When idle timeout cancels, Close() runs cleanup and unblocks.
	_ = closeFDs
	return &xio.Opened{Stream: stream, Label: "STALL"}, nil
}

type multiCloserFuncs []func()

func (m multiCloserFuncs) Close() error {
	for i := len(m) - 1; i >= 0; i-- {
		m[i]()
	}
	return nil
}
