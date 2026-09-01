//go:build linux || darwin

package xio

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

// startOnPTY assigns a PTY slave to cmd stdio (nil slots), starts cmd, closes
// the slave in the parent, and returns the master. setsid and ctty come from
// the spec; pty itself does not start a session or take the controlling tty.
func startOnPTY(cmd *exec.Cmd, s parse.Spec, g *Global) (*os.File, func(), error) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		return nil, nil, err
	}
	// Parent must not keep the slave open after Start (child inherits it).
	defer func() { _ = slave.Close() }()

	if cmd.Stdin == nil {
		cmd.Stdin = slave
	}
	if cmd.Stdout == nil {
		cmd.Stdout = slave
	}
	// stderr stays on the parent unless option stderr.
	if cmd.Stderr == nil && s.BoolOption("stderr") {
		cmd.Stderr = slave
	}
	applyExecPtySession(cmd, s, g)
	// Ctty is the slave FD number as seen by the child after fd setup.
	// Go's fork/exec sets controlling tty from Setctty when slave is Stdin.

	if err := ApplyTermios(int(slave.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	if err := ApplyNamedAttrs(slave.Name(), s, slave); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	unlink, err := CreatePtySlaveLink(s, slave.Name())
	if err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	if err := startWithChildUmask(s, cmd, g); err != nil {
		if unlink != nil {
			unlink()
		}
		logx.CloseQuiet(master)
		return nil, nil, fmt.Errorf("start on pty: %w", err)
	}
	return master, unlink, nil
}
