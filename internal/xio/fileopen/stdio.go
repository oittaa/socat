package fileopen

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func openSTDIO(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
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
	// Classic STDIO: fd 0 read, fd 1 write; options like escape= apply via xio.WrapCommon.
	var stream relay.Stream
	switch mode {
	case xio.ModeRead:
		stream = relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}}
	case xio.ModeWrite:
		stream = relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}}
	default:
		stream = relay.FDStream{
			R: os.Stdin,
			W: os.Stdout,
			C: xio.NopCloser{},
			CloseW: func() error {
				// cannot half-close stdout meaningfully
				return nil
			},
		}
	}
	st, err := xio.WrapCommon(s, stream)
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDIO"}
	switch mode {
	case xio.ModeRead:
		_ = xio.AttachTermios(o, int(os.Stdin.Fd()), s)
	case xio.ModeWrite:
		_ = xio.AttachTermios(o, int(os.Stdout.Fd()), s)
	default:
		_ = xio.AttachTermios(o, int(os.Stdin.Fd()), s)
		if os.Stdout.Fd() != os.Stdin.Fd() {
			_ = xio.AttachTermios(o, int(os.Stdout.Fd()), s)
		}
	}
	return o, nil
}

func openSTDIN(_ context.Context, _ parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeWrite {
		return nil, fmt.Errorf("STDIN is read-only")
	}
	return &xio.Opened{
		Stream: relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}},
		Label:  "STDIN",
	}, nil
}

func openSTDOUT(_ context.Context, _ parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDOUT is write-only")
	}
	return &xio.Opened{
		Stream: relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}},
		Label:  "STDOUT",
	}, nil
}

func openSTDERR(_ context.Context, _ parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDERR is write-only")
	}
	return &xio.Opened{
		Stream: relay.FDStream{R: xio.EOFReader{}, W: os.Stderr, C: xio.NopCloser{}},
		Label:  "STDERR",
	}, nil
}

func openFD(_ context.Context, s parse.Spec, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
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
	return &xio.Opened{
		Stream: relay.RWCStream{ReadWriteCloser: f},
		Label:  fmt.Sprintf("FD:%d", n),
	}, nil
}
