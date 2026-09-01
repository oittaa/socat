package fileopen

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

// openPTY implements PTY: allocate a pseudo-terminal, optionally
// create a symlink to the slave (link=), optionally put master in raw mode (cfmakeraw).
// The transfer stream is the master side; peers open the slave path via the link.
func openPTY(_ context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// PTY takes no positional parameters (PTY::::: probes / PTY_VOIDARG).
	if len(s.Params) > 0 {
		return nil, fmt.Errorf("PTY: wrong number of parameters (expected 0)")
	}
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		return nil, fmt.Errorf("PTY: %w", err)
	}
	// Keep the slave open for the address lifetime. If the last slave FD is
	// closed, reads on the master return EIO and FAKEPTY-style servers exit
	// immediately. Keep a slave FD open while waiting for clients.
	slaveName := slave.Name()

	if g != nil && g.Log != nil {
		g.Log.Noticef("PTY is %s", slaveName)
	}

	if err := xio.ApplyTermios(int(slave.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	if err := xio.ApplyTermios(int(master.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}

	unlink, err := xio.CreatePtySlaveLink(s, slaveName)
	if err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}

	// perm=/user= on PTY apply to the slave node (stat -L follows link).
	if err := xio.ApplyNamedAttrs(slaveName, s, slave); err != nil {
		unlink()
		_ = master.Close()
		_ = slave.Close()
		return nil, err
	}

	// Use xio.PtyStream so half-close does not xio.Close the master (xio.FileStream would).
	st, err := xio.PtyStream(master, s)
	if err != nil {
		unlink()
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		unlink()
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  "PTY:" + slaveName,
	}
	if s.BoolOption("pty-wait-slave") {
		_ = slave.Close()
		slave = nil
		if err := xio.WaitPTYSlave(int(master.Fd()), xio.PTYWaitInterval(s)); err != nil {
			unlink()
			logx.CloseQuiet(master)
			return nil, err
		}
	} else {
		o.AddCleanup(func() { _ = slave.Close() })
	}
	o.AddCleanup(unlink)
	return o, nil
}
