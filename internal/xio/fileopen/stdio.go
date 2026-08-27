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
)

func openSTDIO(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	// Classic MAINSETSID: -,setsid calls setsid(2) in the main process
	// (session leader) before opening EXEC/etc. children.
	if s.BoolOption("setsid") {
		if err := xio.Setsid(); err != nil {
			return nil, fmt.Errorf("setsid: %w", err)
		}
	}
	if err := applyFileLocks(s, os.Stdin, os.Stdout); err != nil {
		return nil, err
	}
	if mode != xio.ModeWrite {
		if err := xio.ApplyFDOptions(os.Stdin, s); err != nil {
			return nil, err
		}
	}
	if mode != xio.ModeRead {
		if err := xio.ApplyFDOptions(os.Stdout, s); err != nil {
			return nil, err
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
		err = attachTermios(o, s, os.Stdin)
	case xio.ModeWrite:
		err = attachTermios(o, s, os.Stdout)
	default:
		err = attachTermios(o, s, os.Stdin, os.Stdout)
	}
	if err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDIN(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeWrite {
		return nil, fmt.Errorf("STDIN is read-only")
	}
	if err := applyFileLocks(s, os.Stdin, nil); err != nil {
		return nil, err
	}
	if err := xio.ApplyFDOptions(os.Stdin, s); err != nil {
		return nil, err
	}
	st, err := xio.WrapCommon(s, relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDIN"}
	if err := attachTermios(o, s, os.Stdin); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDOUT(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDOUT is write-only")
	}
	if err := applyFileLocks(s, nil, os.Stdout); err != nil {
		return nil, err
	}
	if err := xio.ApplyFDOptions(os.Stdout, s); err != nil {
		return nil, err
	}
	st, err := xio.WrapCommon(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDOUT"}
	if err := attachTermios(o, s, os.Stdout); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDERR(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDERR is write-only")
	}
	if err := applyFileLocks(s, nil, os.Stderr); err != nil {
		return nil, err
	}
	if err := xio.ApplyFDOptions(os.Stderr, s); err != nil {
		return nil, err
	}
	st, err := xio.WrapCommon(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stderr, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDERR"}
	if err := attachTermios(o, s, os.Stderr); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openFD(_ context.Context, s parse.Spec, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("FD requires fd number")
	}
	// Classic xioopen_fd applies the contiguous PH_INIT..PH_FD range. That
	// includes PH_PASTSOCKET, but neither PH_PREBIND nor PH_CONNECTED.
	// Reject those combinations explicitly instead of applying them to an
	// existing socket or silently ignoring them on another fd type.
	if err := xio.RejectGenericSetsockoptPhases(s, "FD", xio.SockoptPhasePrebind, xio.SockoptPhaseConnected); err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(s.Params[0])
	if err != nil {
		return nil, fmt.Errorf("FD: %w", err)
	}
	f := os.NewFile(uintptr(n), fmt.Sprintf("fd:%d", n))
	if f == nil {
		return nil, fmt.Errorf("FD:%d invalid", n)
	}
	if err := applyFileLocks(s, f, f); err != nil {
		return nil, err
	}
	if err := xio.ApplyFDOptions(f, s); err != nil {
		return nil, err
	}
	// Classic xioopen_fd applyopts2(PH_INIT, PH_FD) includes PH_PASTSOCKET
	// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is the same).
	if err := xio.ApplySocketOptions(int(f.Fd()), s); err != nil {
		return nil, err
	}
	st, err := xio.WrapCommonAfterConnected(s, relay.RWCStream{ReadWriteCloser: f})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  fmt.Sprintf("FD:%d", n),
	}
	if err := attachTermios(o, s, f); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func attachTermios(o *xio.Opened, s parse.Spec, files ...*os.File) error {
	seen := make(map[uintptr]bool, len(files))
	for _, f := range files {
		if f == nil || seen[f.Fd()] {
			continue
		}
		seen[f.Fd()] = true
		if err := xio.AttachTermios(o, int(f.Fd()), s); err != nil {
			return err
		}
	}
	return nil
}
