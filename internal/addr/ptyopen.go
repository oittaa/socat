package addr

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startOnPTY assigns a PTY slave to cmd stdio (nil slots), starts a new session
// with the slave as controlling TTY, starts cmd, closes the slave in the parent,
// and returns the master. Matches classic EXEC,pty / creack pty.Start behaviour
// for linux and darwin.
func startOnPTY(cmd *exec.Cmd) (*os.File, error) {
	master, slave, err := openPTYPair()
	if err != nil {
		return nil, err
	}
	// Parent must not keep the slave open after Start (child inherits it).
	defer slave.Close()

	if cmd.Stdin == nil {
		cmd.Stdin = slave
	}
	if cmd.Stdout == nil {
		cmd.Stdout = slave
	}
	if cmd.Stderr == nil {
		cmd.Stderr = slave
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	// Ctty is the slave FD number as seen by the child after fd setup.
	// Go's fork/exec sets controlling tty from Setctty when slave is Stdin.

	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, fmt.Errorf("start on pty: %w", err)
	}
	return master, nil
}
