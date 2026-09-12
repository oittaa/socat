package fileopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
)

// openPTY implements PTY: allocate a pseudo-terminal, optionally
// create a symlink to the slave (link=), optionally put master in raw mode (cfmakeraw).
// The transfer stream is the master side; peers open the slave path via the link.
func openPTY(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
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

	if err := xio.ApplyConfiguredTermios(int(slave.Fd()), s.Terminal); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	if err := xio.ApplyConfiguredTermios(int(master.Fd()), s.Terminal); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}

	unlink, err := xio.CreateConfiguredPtySlaveLink(s, slaveName)
	if err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}

	// perm=/user= on PTY apply to the slave node (stat -L follows link).
	if err := xio.ApplyConfiguredNamedAttrs(slaveName, slave, s.File); err != nil {
		unlink()
		_ = master.Close()
		_ = slave.Close()
		return nil, err
	}

	if err := xio.ApplyConfiguredFDOptions(master, s.File, xio.FDSkipOwner); err != nil {
		unlink()
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}

	// Use xio.PtyStream so half-close does not xio.Close the master (xio.FileStream would).
	st, err := xio.PtyStreamConfigured(master, s.Terminal)
	if err != nil {
		unlink()
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	st, err = xio.WrapAfterFD(s, st)
	if err != nil {
		unlink()
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, err
	}
	o := xio.NewReady("PTY:"+slaveName, st)
	if s.Terminal.WaitSlave.Value {
		_ = slave.Close()
		slave = nil
		interval := time.Second
		if s.Terminal.WaitInterval.Set {
			interval = s.Terminal.WaitInterval.Value
		}
		if err := xio.WaitPTYSlave(int(master.Fd()), interval); err != nil {
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
