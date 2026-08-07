package addr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openEXEC(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("EXEC requires command")
	}
	// Classic: spaces separate argv; our parser may have split on ':' so rejoin.
	// Quoted commands land as a single param (e.g. EXEC:"ls -l").
	cmdStr := strings.Join(s.Params, ":")
	return startProcess(ctx, s, mode, g, cmdStr, false)
}

func openSYSTEM(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("SYSTEM requires command")
	}
	cmdStr := strings.Join(s.Params, ":")
	return startProcess(ctx, s, mode, g, cmdStr, true)
}

func openSHELL(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	cmdStr := strings.Join(s.Params, ":")
	if cmdStr == "" {
		cmdStr = os.Getenv("SHELL")
		if cmdStr == "" {
			cmdStr = "/bin/sh"
		}
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	// interactive or -c
	if len(s.Params) == 0 || s.Params[0] == "" {
		return startCmd(ctx, s, mode, g, exec.CommandContext(ctx, shell, "-i"))
	}
	return startCmd(ctx, s, mode, g, exec.CommandContext(ctx, shell, "-c", cmdStr))
}

func startProcess(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmdStr string, useShell bool) (*Opened, error) {
	var cmd *exec.Cmd
	if useShell {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	} else {
		parts := strings.Fields(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
	}
	return startCmd(ctx, s, mode, g, cmd)
}

func startCmd(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	// Default: socketpair communication
	usePipes := s.BoolOption("pipes")
	usePty := s.BoolOption("pty")

	if usePty {
		return nil, fmt.Errorf("EXEC pty option not yet implemented")
	}

	var stream relay.Stream
	var cleanup []func()

	if usePipes {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if s.BoolOption("stderr") {
			cmd.Stderr = os.Stderr
		}
		stream = relay.FDStream{
			R: stdout,
			W: stdin,
			C: multiCloser{},
			CloseW: func() error {
				return stdin.Close()
			},
		}
		cleanup = append(cleanup, func() {
			stdin.Close()
			stdout.Close()
		})
	} else {
		// socketpair
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		parent := os.NewFile(uintptr(fds[0]), "exec-parent")
		child := os.NewFile(uintptr(fds[1]), "exec-child")
		cmd.Stdin = child
		cmd.Stdout = child
		if s.BoolOption("stderr") {
			cmd.Stderr = os.Stderr
		} else {
			cmd.Stderr = child
		}
		stream = relay.RWCStream{ReadWriteCloser: parent}
		cleanup = append(cleanup, func() {
			parent.Close()
			child.Close()
		})
		// child fd must be closed in parent after Start
		defer child.Close()
	}

	if s.BoolOption("setsid") {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}

	if err := cmd.Start(); err != nil {
		for _, f := range cleanup {
			f()
		}
		return nil, err
	}
	// After start with socketpair, close child side in parent — done via defer above for socketpair

	o := &Opened{
		Stream: stream,
		Label:  "EXEC",
	}
	for _, f := range cleanup {
		o.addCleanup(f)
	}
	o.addCleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// Reap in background if process exits
	go func() {
		_ = cmd.Wait()
	}()
	_ = mode
	_ = g
	_ = ctx
	return o, nil
}

