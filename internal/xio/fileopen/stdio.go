package fileopen

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openSTDIO(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	// setsid= calls setsid(2) in the main process (session leader) before
	// opening EXEC/etc. children.
	if s.BoolOption("setsid") {
		if err := xio.Setsid(); err != nil {
			return nil, fmt.Errorf("setsid: %w", err)
		}
	}
	if err := applyFileLocks(s, os.Stdin, os.Stdout); err != nil {
		return nil, err
	}
	if mode != xio.ModeWrite {
		if err := applyInheritedFDAndSocket(os.Stdin, s); err != nil {
			return nil, err
		}
	}
	if mode != xio.ModeRead {
		if err := applyInheritedFDAndSocket(os.Stdout, s); err != nil {
			return nil, err
		}
	}
	// STDIO: fd 0 read, fd 1 write; options like escape= apply via xio.SetupStream.
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
	st, err := xio.SetupStream(s, stream)
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
	if err := applyInheritedFDAndSocket(os.Stdin, s); err != nil {
		return nil, err
	}
	st, err := xio.SetupStream(s, relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}})
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
	if err := applyInheritedFDAndSocket(os.Stdout, s); err != nil {
		return nil, err
	}
	st, err := xio.SetupStream(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}})
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
	if err := applyInheritedFDAndSocket(os.Stderr, s); err != nil {
		return nil, err
	}
	st, err := xio.SetupStream(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stderr, C: xio.NopCloser{}})
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

func openFD(_ context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	n, err := parseFDNum(s)
	if err != nil {
		return nil, err
	}
	// FD applies after-open and after-socket() options, not before-bind or
	// after-connect/accept. Reject those combinations instead of applying
	// them to an existing socket or silently ignoring them.
	if err := xio.RejectGenericSetsockoptPhases(s, s.Type, xio.SockoptPhasePrebind, xio.SockoptPhaseConnected); err != nil {
		return nil, err
	}
	// Default FD_CLOEXEC on the caller's descriptor before options, then
	// I/O on a per-session duplicate so Close cannot close the original
	// unless end-close is set on a non-fork open.
	setInheritedFDCloexec(n, g)
	dupFd, err := duplicateInheritedFD(n)
	if err != nil {
		return nil, fmt.Errorf("FD:%d: %w", n, err)
	}
	f := os.NewFile(uintptr(dupFd), fmt.Sprintf("fd:%d", n))
	if f == nil {
		_ = closeInheritedFD(dupFd)
		return nil, fmt.Errorf("FD:%d invalid", n)
	}
	inheritedSessionLive.Add(1)
	fail := func(err error) (*xio.Opened, error) {
		closeSessionFile(f)
		return nil, err
	}
	if err := applyFileLocks(s, f, f); err != nil {
		return fail(err)
	}
	if err := xio.ApplyFDOptions(f, s); err != nil {
		return fail(err)
	}
	if err := mirrorInheritedFDFlags(n, f, s); err != nil {
		return fail(err)
	}
	// After socket() options (so-priority, …) apply to the inherited fd.
	if err := xio.ApplySocketOptions(int(f.Fd()), s); err != nil {
		return fail(err)
	}
	closeOrig := s.BoolOption("end-close") && (g == nil || !g.ForkChild)
	st, err := xio.SetupConnectedStream(specWithoutEndClose(s), inheritedFDStream(f, n, closeOrig))
	if err != nil {
		return fail(err)
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

// applyInheritedFDAndSocket applies after-open and after-socket() options
// on an inherited descriptor. Bidirectional STDIO applies them on both
// fd 0 and 1. SetupStream is late plus an after-connect/accept fallback, so
// after-socket() options such as so-priority must run here exactly once
// per used descriptor.
func applyInheritedFDAndSocket(f *os.File, s parse.Spec) error {
	if err := xio.ApplyFDOptions(f, s); err != nil {
		return err
	}
	return xio.ApplySocketOptions(int(f.Fd()), s)
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
