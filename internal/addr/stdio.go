package addr

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func openSTDIO(_ context.Context, s parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	// Classic MAINSETSID: -,setsid calls setsid(2) in the main process
	// (session leader) before opening EXEC/etc. children.
	if s.BoolOption("setsid") {
		if _, err := unix.Setsid(); err != nil {
			// EPERM if already a session leader — ignore (same process re-entry).
			if err != unix.EPERM {
				return nil, fmt.Errorf("setsid: %w", err)
			}
		}
	}
	// Classic STDIO: fd 0 read, fd 1 write; options like escape= apply via wrapCommon.
	var stream relay.Stream
	switch mode {
	case ModeRead:
		stream = relay.FDStream{R: os.Stdin, W: discardWriter{}, C: nopCloser{}}
	case ModeWrite:
		stream = relay.FDStream{R: eofReader{}, W: os.Stdout, C: nopCloser{}}
	default:
		stream = relay.FDStream{
			R: os.Stdin,
			W: os.Stdout,
			C: nopCloser{},
			CloseW: func() error {
				// cannot half-close stdout meaningfully
				return nil
			},
		}
	}
	st, err := wrapCommon(s, stream)
	if err != nil {
		return nil, err
	}
	return &Opened{Stream: st, Label: "STDIO"}, nil
}

func openSTDIN(_ context.Context, _ parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if mode == ModeWrite {
		return nil, fmt.Errorf("STDIN is read-only")
	}
	return &Opened{
		Stream: relay.FDStream{R: os.Stdin, W: discardWriter{}, C: nopCloser{}},
		Label:  "STDIN",
	}, nil
}

func openSTDOUT(_ context.Context, _ parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if mode == ModeRead {
		return nil, fmt.Errorf("STDOUT is write-only")
	}
	return &Opened{
		Stream: relay.FDStream{R: eofReader{}, W: os.Stdout, C: nopCloser{}},
		Label:  "STDOUT",
	}, nil
}

func openSTDERR(_ context.Context, _ parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if mode == ModeRead {
		return nil, fmt.Errorf("STDERR is write-only")
	}
	return &Opened{
		Stream: relay.FDStream{R: eofReader{}, W: os.Stderr, C: nopCloser{}},
		Label:  "STDERR",
	}, nil
}

func openFD(_ context.Context, s parse.Spec, _ Mode, _ *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("FD requires fd number")
	}
	n, err := strconv.Atoi(s.Params[0])
	if err != nil {
		return nil, fmt.Errorf("FD: %w", err)
	}
	f := os.NewFile(uintptr(n), fmt.Sprintf("fd:%d", n))
	if f == nil {
		return nil, fmt.Errorf("FD:%d invalid", n)
	}
	return &Opened{
		Stream: relay.RWCStream{ReadWriteCloser: f},
		Label:  fmt.Sprintf("FD:%d", n),
	}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
