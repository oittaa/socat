package addr

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
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

	// fdin/fdout: map socat's pipe ends onto child FDs via a shell exec redirect.
	fdin := s.OptionValue("fdin", "")
	fdout := s.OptionValue("fdout", "")
	if fdin != "" || fdout != "" {
		usePipes = true
		usePty = false
		cmd = rebuildWithFDRedirect(cmd, fdin, fdout)
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
		env = append(env,
			"SOCAT_SOCKADDR="+g.SockAddr,
			"SOCAT_PEERADDR="+g.PeerAddr,
			"SOCAT_SOCKPORT="+g.SockPort,
			"SOCAT_PEERPORT="+g.PeerPort,
		)
		cmd.Env = env
	}

	if usePty {
		return startCmdPty(s, mode, g, cmd)
	}

	var stream relay.Stream
	var cleanup []func()
	var child *os.File

	if usePipes {
		needIn, needOut := pipeDirections(mode, fdin, fdout)
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

	if err := cmd.Start(); err != nil {
		for _, f := range cleanup {
			f()
		}
		if child != nil {
			child.Close()
		}
		return nil, err
	}
	if child != nil {
		child.Close()
	}

	return finishExec(s, g, cmd, stream, cleanup)
}

// startCmdPty runs the child with a pseudo-terminal (classic EXEC/SYSTEM,pty).
//
// Unidirectional dual forms inherit the unused stdio of the socat process:
//   ModeWrite (-!!EXEC,pty): child stdin←PTY, child stdout→os.Stdout (inherit)
//   ModeRead  (EXEC,pty!!-): child stdin←os.Stdin (inherit), child stdout→PTY
// Full duplex: both directions on the PTY slave (pty.Start).
func startCmdPty(s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	var ptmx *os.File
	var err error

	switch mode {
	case ModeWrite:
		// Inherit stdout/stderr; only stdin is the PTY slave.
		master, slave, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("EXEC pty: %w", err)
		}
		ptmx = master
		cmd.Stdin = slave
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		if err := cmd.Start(); err != nil {
			master.Close()
			slave.Close()
			return nil, err
		}
		slave.Close() // child has it
		applyPtyOpts(s, ptmx)
		w := &halfCloseWriter{w: ptmx}
		stream := relay.FDStream{
			R: eofReader{},
			W: w,
			C: multiCloser{},
			CloseW: func() error { w.closeWrite(); return nil },
		}
		return finishExec(s, g, cmd, stream, []func(){func() { ptmx.Close() }})

	case ModeRead:
		// Inherit stdin; only stdout/stderr on PTY slave.
		master, slave, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("EXEC pty: %w", err)
		}
		ptmx = master
		cmd.Stdin = os.Stdin
		cmd.Stdout = slave
		cmd.Stderr = slave
		if err := cmd.Start(); err != nil {
			master.Close()
			slave.Close()
			return nil, err
		}
		slave.Close()
		applyPtyOpts(s, ptmx)
		stream := relay.FDStream{
			R: ptmx,
			W: discardWriter{},
			C: multiCloser{},
			CloseW: func() error { return nil },
		}
		return finishExec(s, g, cmd, stream, []func(){func() { ptmx.Close() }})

	default:
		ptmx, err = pty.Start(cmd)
		if err != nil {
			return nil, fmt.Errorf("EXEC pty: %w", err)
		}
		applyPtyOpts(s, ptmx)
		return finishExec(s, g, cmd, ptyStream(ptmx), []func(){func() { ptmx.Close() }})
	}
}

func applyPtyOpts(s parse.Spec, ptmx *os.File) {
	if s.BoolOption("cfmakeraw") || s.BoolOption("raw") || s.BoolOption("rawer") ||
		s.HasOption("cfmakeraw") || s.HasOption("raw") {
		_ = setRaw(int(ptmx.Fd()))
		return
	}
	if v := s.OptionValue("echo", ""); v == "0" || (s.HasOption("echo") && !s.BoolOption("echo")) {
		_ = setTermiosFlag(int(ptmx.Fd()), false, true)
	}
	if v := s.OptionValue("opost", ""); v == "0" || (s.HasOption("opost") && !s.BoolOption("opost")) {
		_ = setTermiosFlag(int(ptmx.Fd()), true, false)
	}
}

func finishExec(s parse.Spec, g *Global, cmd *exec.Cmd, stream relay.Stream, cleanup []func()) (*Opened, error) {
	st, err := wrapCommon(s, stream)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		for _, f := range cleanup {
			f()
		}
		return nil, err
	}

	// Track child exit for EXEC_RC / SYSTEM_RC.
	var mu sync.Mutex
	var waitErr error
	var exitCode int
	done := make(chan struct{})
	go func() {
		err := cmd.Wait()
		mu.Lock()
		waitErr = err
		if err == nil {
			exitCode = 0
		} else if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
		mu.Unlock()
		close(done)
	}()

	// How long to wait for child flush after transfer ends (classic -t linger).
	linger := 500 * time.Millisecond
	if g != nil && g.Linger > 0 {
		linger = g.Linger
	}
	// shut-none: do not kill the child; wait for natural exit (with a cap).
	shutNone := s.BoolOption("shut-none") || s.OptionValue("shut", "") == "none"

	o := &Opened{
		Stream: st,
		Label:  "EXEC",
	}
	for _, f := range cleanup {
		o.addCleanup(f)
	}
	o.addCleanup(func() {
		// Give write-only children (od -c) time to flush after stdin EOF.
		waitFor := linger
		if shutNone {
			waitFor = 5 * time.Second
		}
		killed := false
		select {
		case <-done:
		case <-time.After(waitFor):
			if !shutNone {
				killed = true
				_ = cmd.Process.Kill()
			}
			<-done
		}
		// Promote only natural non-zero exits (false/exit 1), not kills/SIGHUP
		// from closing a PTY master (those yield 255/signal and must not fail echo tests).
		mu.Lock()
		code := exitCode
		werr := waitErr
		mu.Unlock()
		if killed {
			return
		}
		if code != 0 && g != nil {
			// Signal deaths: Go reports -1; classic 128+n. Not EXEC_RC failures
			// (PTY master close often SIGHUPs cat after a successful echo).
			if code < 0 || code >= 128 {
				return
			}
			g.ChildExitCode = code
			if werr != nil {
				g.ChildErr = werr
			}
		}
	})
	return o, nil
}

func pipeDirections(mode Mode, fdin, fdout string) (needIn, needOut bool) {
	if fdin != "" && fdout == "" {
		return true, false
	}
	if fdout != "" && fdin == "" {
		return false, true
	}
	if fdin != "" && fdout != "" {
		return true, true
	}
	switch mode {
	case ModeRead:
		// Only reading from child: inherit process stdin for the child.
		return false, true
	case ModeWrite:
		// Only writing to child: inherit process stdout from the child.
		return true, false
	default:
		return true, true
	}
}

func rebuildWithFDRedirect(cmd *exec.Cmd, fdin, fdout string) *exec.Cmd {
	orig := ""
	if len(cmd.Args) > 0 {
		if cmd.Args[0] == "/bin/sh" || cmd.Args[0] == "sh" || strings.HasSuffix(cmd.Path, "/sh") {
			if len(cmd.Args) >= 3 && cmd.Args[1] == "-c" {
				orig = cmd.Args[2]
			}
		} else {
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
	return exec.Command("/bin/sh", "-c", redir+"; "+orig)
}

func setTermiosFlag(fd int, clearOPost, clearEcho bool) error {
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	if clearOPost {
		termios.Oflag &^= unix.OPOST
	}
	if clearEcho {
		termios.Lflag &^= unix.ECHO | unix.ECHONL
	}
	return unix.IoctlSetTermios(fd, unix.TCSETS, termios)
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
