package fileopen

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openSTDIO(ctx context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	config, err := preparedFileConfig(ctx)
	if err != nil {
		return nil, err
	}
	// setsid= calls setsid(2) in the main process (session leader) before
	// opening EXEC/etc. children.
	if config.Process.SetSID.Value {
		if err := xio.Setsid(); err != nil {
			return nil, fmt.Errorf("setsid: %w", err)
		}
	}
	if err := applyConfiguredFileLocks(config.File, os.Stdin, os.Stdout); err != nil {
		return nil, err
	}
	if mode != xio.ModeWrite {
		if err := applyInheritedFDAndSocket(os.Stdin, s, config); err != nil {
			return nil, err
		}
	}
	if mode != xio.ModeRead {
		if err := applyInheritedFDAndSocket(os.Stdout, s, config); err != nil {
			return nil, err
		}
	}
	// STDIO: fd 0 read, fd 1 write; options like escape= apply via WrapAfterFD.
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
	st, err := xio.WrapAfterFD(s, stream)
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDIO"}
	switch mode {
	case xio.ModeRead:
		err = attachConfiguredTermios(o, config, os.Stdin)
	case xio.ModeWrite:
		err = attachConfiguredTermios(o, config, os.Stdout)
	default:
		err = attachConfiguredTermios(o, config, os.Stdin, os.Stdout)
	}
	if err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDIN(ctx context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	config, err := preparedFileConfig(ctx)
	if err != nil {
		return nil, err
	}
	if mode == xio.ModeWrite {
		return nil, fmt.Errorf("STDIN is read-only")
	}
	if err := applyConfiguredFileLocks(config.File, os.Stdin, nil); err != nil {
		return nil, err
	}
	if err := applyInheritedFDAndSocket(os.Stdin, s, config); err != nil {
		return nil, err
	}
	st, err := xio.WrapAfterFD(s, relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDIN"}
	if err := attachConfiguredTermios(o, config, os.Stdin); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDOUT(ctx context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	config, err := preparedFileConfig(ctx)
	if err != nil {
		return nil, err
	}
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDOUT is write-only")
	}
	if err := applyConfiguredFileLocks(config.File, nil, os.Stdout); err != nil {
		return nil, err
	}
	if err := applyInheritedFDAndSocket(os.Stdout, s, config); err != nil {
		return nil, err
	}
	st, err := xio.WrapAfterFD(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDOUT"}
	if err := attachConfiguredTermios(o, config, os.Stdout); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openSTDERR(ctx context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	config, err := preparedFileConfig(ctx)
	if err != nil {
		return nil, err
	}
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("STDERR is write-only")
	}
	if err := applyConfiguredFileLocks(config.File, nil, os.Stderr); err != nil {
		return nil, err
	}
	if err := applyInheritedFDAndSocket(os.Stderr, s, config); err != nil {
		return nil, err
	}
	st, err := xio.WrapAfterFD(s, relay.FDStream{R: xio.EOFReader{}, W: os.Stderr, C: xio.NopCloser{}})
	if err != nil {
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "STDERR"}
	if err := attachConfiguredTermios(o, config, os.Stderr); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func openFD(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	config, err := preparedFileConfig(ctx)
	if err != nil {
		return nil, err
	}
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
	if err := applyConfiguredFileLocks(config.File, f, f); err != nil {
		return fail(err)
	}
	if err := xio.ApplyConfiguredFDOptions(f, config.File, xio.FDSkip{}); err != nil {
		return fail(err)
	}
	if err := mirrorInheritedFDFlags(n, f, config.File); err != nil {
		return fail(err)
	}
	// After socket() options (so-priority, …) apply to the inherited fd.
	if err := xio.ApplySocketOptions(int(f.Fd()), s); err != nil {
		return fail(err)
	}
	closeOrig := config.Transfer.EndClose.Value && (g == nil || !g.ForkChild)
	st, err := xio.WrapOpened(specWithoutEndClose(s), inheritedFDStream(f, n, closeOrig))
	if err != nil {
		return fail(err)
	}
	o := &xio.Opened{
		Stream: st,
		Label:  fmt.Sprintf("FD:%d", n),
	}
	if err := attachConfiguredTermios(o, config, f); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

// applyInheritedFDAndSocket applies after-open and after-socket() options
// on an inherited descriptor. Bidirectional STDIO applies them on both
// fd 0 and 1. After-socket() options such as so-priority run here
// exactly once per used descriptor. WrapAfterFD then applies leftover
// after-connect/accept sockopts and stream wrappers.
func applyInheritedFDAndSocket(f *os.File, s parse.Spec, config addrconfig.Address) error {
	if err := xio.ApplyConfiguredFDOptions(f, config.File, xio.FDSkip{}); err != nil {
		return err
	}
	return xio.ApplySocketOptions(int(f.Fd()), s)
}

func attachConfiguredTermios(o *xio.Opened, config addrconfig.Address, files ...*os.File) error {
	seen := make(map[uintptr]bool, len(files))
	for _, f := range files {
		if f == nil || seen[f.Fd()] {
			continue
		}
		seen[f.Fd()] = true
		if err := xio.AttachConfiguredTermios(o, int(f.Fd()), config.Terminal); err != nil {
			return err
		}
	}
	return nil
}
