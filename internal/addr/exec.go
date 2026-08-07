package addr

import (
	"context"
	"fmt"
	"io"
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
		// Preserve intentional spaces inside quoted segments (already unquoted by parser).
		// Split on whitespace for argv; classic EXEC uses simple space separation.
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
	}
	return startCmd(ctx, s, mode, g, cmd)
}

// splitExecArgs splits an EXEC command line on whitespace, collapsing runs of spaces
// the same way classic socat does for unquoted commands.
func splitExecArgs(s string) []string {
	return strings.Fields(s)
}

func startCmd(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	// Default: socketpair for full duplex; pipes when requested or unidirectional
	// so unused direction can inherit process stdio (classic LISTENENV / single-exec).
	usePipes := s.BoolOption("pipes") || mode == ModeRead || mode == ModeWrite
	usePty := s.BoolOption("pty")

	if usePty {
		return nil, fmt.Errorf("EXEC pty option not yet implemented")
	}

	// fdin/fdout: map socat's pipe ends onto child FDs via a shell exec redirect.
	// Classic: fdin=8,fdout=9 with command using those descriptors.
	fdin := s.OptionValue("fdin", "")
	fdout := s.OptionValue("fdout", "")
	if fdin != "" || fdout != "" {
		usePipes = true // need separate in/out pipes
		// Rebuild command as: sh -c 'exec N<&0 M>&1; original...'
		orig := strings.Join(cmd.Args, " ")
		if cmd.Path != "" && len(cmd.Args) > 0 {
			// Args[0] is usually the program name
			parts := append([]string{}, cmd.Args...)
			orig = strings.Join(parts, " ")
		}
		// Prefer Args reconstruction for Command
		if len(cmd.Args) > 0 {
			// For Command("sh","-c", script), Args are already set
			if cmd.Args[0] == "/bin/sh" || cmd.Args[0] == "sh" || strings.HasSuffix(cmd.Path, "/sh") {
				if len(cmd.Args) >= 3 && cmd.Args[1] == "-c" {
					orig = cmd.Args[2]
				}
			} else {
				// quote-free join; classic test commands are simple
				orig = shellJoin(cmd.Args)
			}
		}
		redir := "exec"
		if fdin != "" {
			redir += " " + fdin + "<&0"
		}
		if fdout != "" {
			redir += " " + fdout + ">&1"
		}
		script := redir + "; " + orig
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}

	var stream relay.Stream
	var cleanup []func()
	var child *os.File

	if usePipes {
		// With fdin/fdout, only create pipes for the directions that are remapped.
		// Classic dual-SYSTEM tests rely on the other direction inheriting process
		// stdio so data can enter/leave via the dual address alone.
		//
		// Similarly, single-direction EXEC (ModeRead / ModeWrite) should inherit
		// the unused stdio of the socat process (classic "inheritance" tests).
		needIn := true
		needOut := true
		if fdin != "" && fdout == "" {
			needIn, needOut = true, false
		} else if fdout != "" && fdin == "" {
			needIn, needOut = false, true
		} else if fdin != "" && fdout != "" {
			needIn, needOut = true, true
		} else {
			switch mode {
			case ModeRead:
				// Only reading from child: inherit process stdin for the child.
				needIn, needOut = false, true
			case ModeWrite:
				// Only writing to child: inherit process stdout from the child.
				needIn, needOut = true, false
			default:
				needIn, needOut = true, true
			}
		}

		var stdin io.WriteCloser
		var stdout io.ReadCloser
		var err error

		if needIn {
			stdin, err = cmd.StdinPipe()
			if err != nil {
				return nil, err
			}
		} else {
			cmd.Stdin = os.Stdin
		}
		if needOut {
			stdout, err = cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}
		} else {
			cmd.Stdout = os.Stdout
		}
		if s.BoolOption("stderr") {
			cmd.Stderr = os.Stderr
		}

		var r io.Reader = stdout
		var w io.Writer = stdin
		if stdout == nil {
			r = eofReader{}
		}
		if stdin == nil {
			w = discardWriter{}
		}
		stream = relay.FDStream{
			R: r,
			W: w,
			C: multiCloser{},
			CloseW: func() error {
				if stdin != nil {
					return stdin.Close()
				}
				return nil
			},
		}
		cleanup = append(cleanup, func() {
			if stdin != nil {
				stdin.Close()
			}
			if stdout != nil {
				stdout.Close()
			}
		})
	} else {
		// socketpair — must SHUT_WR so child sees EOF on stdin (classic behavior)
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		parent := os.NewFile(uintptr(fds[0]), "exec-parent")
		child = os.NewFile(uintptr(fds[1]), "exec-child")
		cmd.Stdin = child
		cmd.Stdout = child
		if s.BoolOption("stderr") {
			cmd.Stderr = os.Stderr
		} else {
			cmd.Stderr = child
		}
		stream = fileStream(parent)
		cleanup = append(cleanup, func() {
			parent.Close()
		})
	}

	if s.BoolOption("setsid") {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
	}

	// Inject classic SOCAT_* connection environment for SYSTEM/EXEC children.
	if g != nil {
		env := append([]string{}, os.Environ()...)
		// Always set the four vars (empty if unknown) so scripts can rely on them.
		env = append(env,
			"SOCAT_SOCKADDR="+g.SockAddr,
			"SOCAT_PEERADDR="+g.PeerAddr,
			"SOCAT_SOCKPORT="+g.SockPort,
			"SOCAT_PEERPORT="+g.PeerPort,
		)
		cmd.Env = env
	}

	// Promote child failure: if nofork semantics requested later; for now Start errors fail open.
	if err := cmd.Start(); err != nil {
		for _, f := range cleanup {
			f()
		}
		if child != nil {
			child.Close()
		}
		return nil, err
	}
	// Close child end in parent so only the process holds it.
	if child != nil {
		child.Close()
	}

	st, err := wrapCommon(s, stream)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		for _, f := range cleanup {
			f()
		}
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	o := &Opened{
		Stream: st,
		Label:  "EXEC",
	}
	for _, f := range cleanup {
		o.addCleanup(f)
	}
	o.addCleanup(func() {
		// Prefer graceful exit after half-close; only force-kill if still running.
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
			<-done
		}
	})
	_ = mode
	_ = g
	_ = ctx
	return o, nil
}

func shellJoin(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t'\"\\$`") {
			b.WriteByte('\'')
			b.WriteString(strings.ReplaceAll(a, "'", `'\''`))
			b.WriteByte('\'')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

