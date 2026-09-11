//go:build linux || darwin

package xio

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// rejectExecUnsupportedPTYOptions rejects wait-slave / pty-interval on
// EXEC/SYSTEM/SHELL. Those options apply only to the PTY address.
func rejectExecUnsupportedPTYOptions(s parse.Spec) error {
	for _, name := range []string{"pty-wait-slave", "pty-interval"} {
		if o, ok := s.OptionNamed(name); ok {
			return fmt.Errorf("%s: %s is not supported", s.Type, o.OriginalSpelling())
		}
	}
	return nil
}

// applyExecPtySession applies explicit setsid/ctty requests. TIOCSCTTY cannot
// succeed without a new session, so ctty alone warns and leaves it unchanged.
func applyExecPtySession(cmd *exec.Cmd, s parse.Spec, g *Global) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = s.BoolOption("setsid")
	wantCtty := s.BoolOption("ctty")
	if wantCtty && cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setctty = true
		return
	}
	cmd.SysProcAttr.Setctty = false
	if wantCtty && g != nil && g.Log != nil {
		g.Log.Warningf("ctty: TIOCSCTTY skipped; child is not a session leader")
	}
}

// openExecPTYPair allocates a PTY pair for an EXEC child, applies session/
// controlling-terminal attributes, and configures slave termios.
func openExecPTYPair(cmd *exec.Cmd, s parse.Spec, g *Global) (*os.File, *os.File, func(), error) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("EXEC pty: %w", err)
	}
	applyExecPtySession(cmd, s, g)
	if err := ApplyTermios(int(slave.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	// Apply master termios before Start. A later TIOCSETA on Darwin's
	// controller flushes t_outq and can discard already-written child output.
	if err := ApplyTermios(int(master.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	// perm/user/group apply to the PTY slave. Applying them to the master
	// changes the wrong descriptor and can fail differently across platforms.
	if err := ApplyNamedAttrs(slave.Name(), s, slave); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	unlink, err := CreatePtySlaveLink(s, slave.Name())
	if err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	return master, slave, unlink, nil
}

// closeExecPTY closes both PTY ends after a failed child start.
func closeExecPTY(master, slave *os.File) {
	logx.CloseQuiet(master)
	logx.CloseQuiet(slave)
}

// startPtyFDRedirect keeps the PTY slave as ExtraFiles fd 3 and lets the
// descriptor mapper duplicate it onto fdi/fdo. fdin/fdout do not select pipes.
func (c *execChild) startPtyFDRedirect(ctx context.Context) (*Opened, error) {
	master, slave, unlink, err := openExecPTYPair(c.cmd, c.spec, c.g)
	if err != nil {
		return nil, err
	}
	c.cmd.ExtraFiles = []*os.File{slave}
	c.cmd.Stdin = os.Stdin
	c.cmd.Stdout = os.Stdout
	c.cmd.Stderr = os.Stderr
	if c.cmd.SysProcAttr == nil {
		c.cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.cmd.SysProcAttr.Ctty = 3
	if err := c.start(ctx); err != nil {
		if unlink != nil {
			unlink()
		}
		closeExecPTY(master, slave)
		return nil, err
	}
	if c.mode == ModeWrite {
		logx.CloseQuiet(slave)
	}
	if err := applyPtyMasterLifecycle(c.spec, master); err != nil {
		c.killWait()
		if unlink != nil {
			unlink()
		}
		closeExecPTY(master, slave)
		return nil, err
	}
	var stream relay.Stream
	waitChild := false
	var done chan struct{}
	var closeSlave func()
	switch c.mode {
	case ModeWrite:
		w := &halfCloseWriter{w: master}
		stream = relay.FDStream{
			R:      EOFReader{},
			W:      w,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { w.closeWrite(); return nil },
		}
		waitChild = true
	case ModeRead:
		done = make(chan struct{})
		r, closeHeldSlave, rerr := execPTYMasterReader(master, slave, c.spec, done)
		if rerr != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			logx.CloseQuiet(master)
			return nil, rerr
		}
		closeSlave = closeHeldSlave
		stream = relay.FDStream{
			R:      r,
			W:      io.Discard,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { return nil },
		}
	default:
		done = make(chan struct{})
		r, closeHeldSlave, rerr := execPTYMasterReader(master, slave, c.spec, done)
		if rerr != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			logx.CloseQuiet(master)
			return nil, rerr
		}
		closeSlave = closeHeldSlave
		stream = ptyExecStream(master, r)
	}
	return c.finishAfterFD(stream, execPtyCleanup(master, unlink, closeSlave), waitChild, done)
}

// startPty runs the child with a pseudo-terminal.
//
// Unidirectional dual forms inherit the unused stdio of the socat process:
//
//	ModeWrite (-!!EXEC,pty): child stdin←PTY, child stdout→os.Stdout (inherit)
//	ModeRead  (EXEC,pty!!-): child stdin←os.Stdin (inherit), child stdout→PTY
//
// Full duplex: both directions on the PTY slave (startOnPTY).
func (c *execChild) startPty(ctx context.Context) (*Opened, error) {
	if c.fdRedirect {
		return c.startPtyFDRedirect(ctx)
	}
	var ptmx *os.File
	var unlink func()
	var err error

	switch c.mode {
	case ModeWrite:
		// Inherit stdout/stderr; only stdin is the PTY slave.
		master, slave, u, err := openExecPTYPair(c.cmd, c.spec, c.g)
		if err != nil {
			return nil, err
		}
		unlink = u
		ptmx = master
		c.cmd.Stdin = slave
		c.cmd.Stdout = os.Stdout
		if c.spec.BoolOption("stderr") {
			c.cmd.Stderr = slave
		}
		if err := c.start(ctx); err != nil {
			if unlink != nil {
				unlink()
			}
			closeExecPTY(master, slave)
			return nil, err
		}
		logx.CloseQuiet(slave)
		if err := applyPtyMasterLifecycle(c.spec, ptmx); err != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			logx.CloseQuiet(ptmx)
			return nil, err
		}
		w := &halfCloseWriter{w: ptmx}
		stream := relay.FDStream{
			R:      EOFReader{},
			W:      w,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { w.closeWrite(); return nil },
		}
		return c.finishAfterFD(stream, execPtyCleanup(ptmx, unlink, nil), true, nil)

	case ModeRead:
		// Inherit stdin; only stdout/stderr on PTY slave.
		master, slave, u, err := openExecPTYPair(c.cmd, c.spec, c.g)
		if err != nil {
			return nil, err
		}
		unlink = u
		ptmx = master
		c.cmd.Stdin = os.Stdin
		c.cmd.Stdout = slave
		if c.spec.BoolOption("stderr") {
			c.cmd.Stderr = slave
		}
		// Controlling tty is stdout/stderr slave; Setctty needs a child FD.
		// With stdin inherited, Ctty 1 (stdout) is the slave after setup.
		if c.cmd.SysProcAttr == nil {
			c.cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		c.cmd.SysProcAttr.Ctty = 1
		if err := c.start(ctx); err != nil {
			if unlink != nil {
				unlink()
			}
			closeExecPTY(master, slave)
			return nil, err
		}
		if err := applyPtyMasterLifecycle(c.spec, ptmx); err != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			closeExecPTY(ptmx, slave)
			return nil, err
		}
		done := make(chan struct{})
		r, closeSlave, rerr := execPTYMasterReader(ptmx, slave, c.spec, done)
		if rerr != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			logx.CloseQuiet(ptmx)
			return nil, rerr
		}
		stream := relay.FDStream{
			R:      r,
			W:      io.Discard,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { return nil },
		}
		return c.finishAfterFD(stream, execPtyCleanup(ptmx, unlink, closeSlave), false, done)

	default:
		var slave *os.File
		ptmx, slave, unlink, err = c.startOnPTY(ctx)
		if err != nil {
			return nil, fmt.Errorf("EXEC pty: %w", err)
		}
		if err := applyPtyMasterLifecycle(c.spec, ptmx); err != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			closeExecPTY(ptmx, slave)
			return nil, err
		}
		done := make(chan struct{})
		r, closeSlave, rerr := execPTYMasterReader(ptmx, slave, c.spec, done)
		if rerr != nil {
			c.killWait()
			if unlink != nil {
				unlink()
			}
			logx.CloseQuiet(ptmx)
			return nil, rerr
		}
		st := ptyExecStream(ptmx, r)
		return c.finishAfterFD(st, execPtyCleanup(ptmx, unlink, closeSlave), false, done)
	}
}

// startOnPTY assigns a PTY slave to cmd stdio (nil slots), starts the child,
// and returns both ends. The caller owns both descriptors. setsid and ctty
// come from the spec; pty itself does not start a session or take the
// controlling tty.
func (c *execChild) startOnPTY(ctx context.Context) (*os.File, *os.File, func(), error) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		return nil, nil, nil, err
	}

	if c.cmd.Stdin == nil {
		c.cmd.Stdin = slave
	}
	if c.cmd.Stdout == nil {
		c.cmd.Stdout = slave
	}
	// stderr stays on the parent unless option stderr.
	if c.cmd.Stderr == nil && c.spec.BoolOption("stderr") {
		c.cmd.Stderr = slave
	}
	applyExecPtySession(c.cmd, c.spec, c.g)
	// Ctty is the slave FD number as seen by the child after fd setup.
	// Go's fork/exec sets controlling tty from Setctty when slave is Stdin.

	if err := ApplyTermios(int(slave.Fd()), c.spec); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	// Before Start: Darwin TIOCSETA on the controller flushes t_outq.
	if err := ApplyTermios(int(master.Fd()), c.spec); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	if err := ApplyNamedAttrs(slave.Name(), c.spec, slave); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	unlink, err := CreatePtySlaveLink(c.spec, slave.Name())
	if err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, err
	}
	if err := c.start(ctx); err != nil {
		if unlink != nil {
			unlink()
		}
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, nil, fmt.Errorf("start on pty: %w", err)
	}
	return master, slave, unlink, nil
}

func execPtyCleanup(master *os.File, unlink, closeSlave func()) []func() {
	out := []func(){func() { logx.CloseQuiet(master) }}
	if unlink != nil {
		out = append(out, unlink)
	}
	if closeSlave != nil {
		out = append(out, closeSlave)
	}
	return out
}

func applyPtyMasterLifecycle(s parse.Spec, ptmx *os.File) error {
	return ApplyFDOptionsSkip(ptmx, s, FDSkipOwner)
}
