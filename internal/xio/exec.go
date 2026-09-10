//go:build linux || darwin

package xio

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openEXEC(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("EXEC requires command")
	}
	// Spaces separate argv; the address parser may have split on ':' so rejoin.
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
	hasCommand := len(s.Params) > 0 && s.Params[0] != ""
	return startCmd(ctx, s, mode, g, shellCommand(ctx, s, cmdStr, hasCommand))
}

// shellCommand builds SHELL as $SHELL (or shell=/bin/sh) with argv0 as the
// basename and optional -c command. nofork rebuilds via runExecNoFork, so
// shell= and $SHELL are honored in one place.
func shellCommand(ctx context.Context, s parse.Spec, cmdStr string, hasCommand bool) *exec.Cmd {
	shell := s.OptionValue("shell", "")
	if shell == "" {
		shell = os.Getenv("SHELL")
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	argv0 := filepath.Base(shell)
	if !hasCommand {
		cmd := exec.CommandContext(ctx, shell) // #nosec G204 G702 -- EXEC/SYSTEM/SHELL runs the command from the address line
		cmd.Args = []string{argv0}
		return cmd
	}
	cmd := exec.CommandContext(ctx, shell, "-c", cmdStr) // #nosec G204 G702 -- EXEC/SYSTEM/SHELL runs the command from the address line
	cmd.Args[0] = argv0
	return cmd
}

func startProcess(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmdStr string, useShell bool) (*Opened, error) {
	var cmd *exec.Cmd
	if useShell {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	} else {
		// Split on whitespace for argv.
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	}
	return startCmd(ctx, s, mode, g, cmd)
}

// applyExecChildOptions applies dash/login and setpgid on the child *exec.Cmd.
// dash prefixes argv[0] with '-' on EXEC only; SYSTEM/SHELL reject it.
// setpgid: omitted, 0, and 1 all make a new process group (Pgid=0). Do not
// pass Pgid=1: Linux setpgid(0, 1) is EPERM and would fail Start.
func applyExecChildOptions(s parse.Spec, cmd *exec.Cmd) error {
	if err := applyDashArgv0(s, cmd); err != nil {
		return err
	}
	return applySetpgid(s, cmd)
}

func applyDashArgv0(s parse.Spec, cmd *exec.Cmd) error {
	o, ok := s.OptionNamed("dash")
	if !ok {
		return nil
	}
	if !strings.EqualFold(s.Type, "EXEC") {
		return fmt.Errorf("%s: unused on %s", o.OriginalSpelling(), s.Type)
	}
	if !s.BoolOption("dash") {
		return nil
	}
	if cmd == nil || len(cmd.Args) == 0 {
		return fmt.Errorf("dash: no argv to rewrite")
	}
	base := filepath.Base(cmd.Args[0])
	if base == "." || base == "/" {
		base = cmd.Args[0]
	}
	if !strings.HasPrefix(base, "-") {
		cmd.Args[0] = "-" + base
	}
	return nil
}

func applySetpgid(s parse.Spec, cmd *exec.Cmd) error {
	o, ok := s.OptionNamed("setpgid")
	if !ok {
		return nil
	}
	n := 1 // bare flag stores 1
	if o.Has {
		v, err := ParseIntAny(o.Value)
		if err != nil {
			return fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
		}
		n = v
	}
	// Omitted, 0, and 1 → new process group. Pgid=0 is setpgid(0, 0).
	// Do not pass Pgid=1: Linux setpgid(0, 1) is EPERM.
	pgid := n
	if n == 0 || n == 1 {
		pgid = 0
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = pgid
	return nil
}

// splitExecArgs splits an EXEC command line: unquoted runs of spaces
// separate args (no empty args from bare spaces); double-quoted segments
// keep spaces and may be empty ("" → empty arg); \" inside quotes is a
// literal quote (so -c 'echo "$1"' works).
func splitExecArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inDouble := false
	escape := false
	// sawQuote marks a quoted segment so "" becomes an empty argument.
	sawQuote := false

	flush := func() {
		if sawQuote || cur.Len() > 0 {
			args = append(args, cur.String())
		}
		cur.Reset()
		sawQuote = false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			cur.WriteByte(c)
			escape = false
			continue
		}
		if c == '\\' && inDouble {
			escape = true
			continue
		}
		if c == '"' {
			inDouble = !inDouble
			sawQuote = true
			continue // drop delimiter
		}
		if !inDouble && (c == ' ' || c == '\t') {
			flush()
			// collapse consecutive unquoted whitespace
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	return args
}

// commandForExecSpec builds argv for EXEC, SYSTEM, or SHELL. Start comes later.
func commandForExecSpec(ctx context.Context, s parse.Spec) (*exec.Cmd, error) {
	cmdStr := strings.Join(s.Params, ":")
	switch {
	case strings.EqualFold(s.Type, "SHELL"):
		hasCommand := len(s.Params) > 0 && s.Params[0] != ""
		return shellCommand(ctx, s, cmdStr, hasCommand), nil
	case strings.EqualFold(s.Type, "SYSTEM"):
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
		return cmd, nil
	default:
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
		return cmd, nil
	}
}

// childWaitExitCode maps cmd.Wait to a process exit status. Go's
// exec.ExitError.ExitCode is -1 when the child was signaled; POSIX shells
// report 128+signum. Forked EXEC still skips those statuses in finishExec
// so a PTY-master SIGHUP does not become EXEC_RC.
func childWaitExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return 0, false
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true
	}
	return ee.ExitCode(), true
}

func asOSFile(x any) *os.File {
	if x == nil {
		return nil
	}
	if f, ok := x.(*os.File); ok {
		return f
	}
	// Dual addresses nest their read and write endpoints inside an outer
	// FDStream. nofork still needs to discover the actual inherited files.
	switch stream := x.(type) {
	case relay.FDStream:
		if f := asOSFile(stream.R); f != nil {
			return f
		}
		return asOSFile(stream.W)
	case relay.RWCStream:
		return asOSFile(stream.ReadWriteCloser)
	}
	if u, ok := x.(interface{ UnwrapStream() relay.Stream }); ok {
		return asOSFile(u.UnwrapStream())
	}
	// ignoreEOF and similar wrappers that expose Fd/underlying file
	if u, ok := x.(interface{ Unwrap() any }); ok {
		return asOSFile(u.Unwrap())
	}
	return nil
}

// rejectUnusedExecPastSocketOptions fails when an after-socket option would
// be silently ignored on EXEC/SYSTEM/SHELL pipes, pty, or nofork. Canonical
// Name is after alias fold. end-close is not pipes; it keeps the default
// socketpair and applies those options on the child endpoint.
func rejectUnusedExecPastSocketOptions(s parse.Spec) error {
	for _, o := range s.Options {
		if isPastSocketActionOption(o) {
			return fmt.Errorf("option %q not inquired", o.Name)
		}
	}
	return nil
}

// execChild is one EXEC/SYSTEM/SHELL start after argv exists.
// Forked: prepare → open transport FDs → Start → drop child-side FDs → finishExec.
// nofork: prepare → attach peer as stdio → Start → drop ExtraFiles → Wait.
type execChild struct {
	spec       parse.Spec
	mode       Mode
	g          *Global
	cmd        *exec.Cmd
	fdin       string
	fdout      string
	fdRedirect bool
	usePipes   bool
	usePty     bool
}

func newExecChild(s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*execChild, error) {
	fdin, fdout, err := processFDPair(s, mode)
	if err != nil {
		return nil, err
	}
	return &execChild{
		spec:       s,
		mode:       mode,
		g:          g,
		cmd:        cmd,
		fdin:       fdin,
		fdout:      fdout,
		fdRedirect: fdin != "" || fdout != "",
	}, nil
}

// applyExecProcessAttrs sets chdir, setsid, dash/setpgid, and SOCAT_* env.
func applyExecProcessAttrs(s parse.Spec, cmd *exec.Cmd, g *Global, fdRedirect bool) error {
	cmd.Dir = s.OptionValue("chdir", "")
	if s.BoolOption("setsid") {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
	}
	if fdRedirect {
		if err := applySetpgid(s, cmd); err != nil {
			return err
		}
	} else if err := applyExecChildOptions(s, cmd); err != nil {
		return err
	}
	if g != nil {
		cmd.Env = childEnviron(g)
	}
	if fdRedirect {
		cmd.Env = withExecFDHelperEnv(cmd.Env)
	}
	return nil
}

func (c *execChild) wrapForkedFDHelper(ctx context.Context) error {
	if !c.fdRedirect {
		return nil
	}
	// dash changes the target's argv[0], not the internal helper used to
	// place fdi/fdo. Apply it before wrapping. Every custom fdin/fdout
	// uses the child dup2 helper so bare SHELL and dash stay on the
	// target instead of a /bin/sh reconstruction.
	if err := applyDashArgv0(c.spec, c.cmd); err != nil {
		return err
	}
	var err error
	if c.usePipes {
		c.cmd, err = rebuildWithPipeFDHelper(ctx, c.cmd, c.mode, c.fdin, c.fdout, c.spec.BoolOption("stderr"))
	} else {
		// Socketpair and PTY share ExtraFiles[0] (child fd 3).
		c.cmd, err = rebuildWithSocketFDHelper(ctx, c.cmd, c.mode, c.fdin, c.fdout, c.spec.BoolOption("stderr"))
	}
	return err
}

func (c *execChild) prepareForked(ctx context.Context) error {
	if err := rejectExecUnsupportedPTYOptions(c.spec); err != nil {
		return err
	}
	userPipes := c.spec.BoolOption("pipes")
	c.usePty = execUsesPTY(c.spec)
	// Forked EXEC/SYSTEM/SHELL defaults to socketpair, including unidirectional
	// mode and fdin/fdout. fdin/fdout only change Dup2 targets. pipes and
	// pty/ptmx/openpty are user-selected transports; pipes+pty ignores pipes.
	c.usePipes = userPipes
	if c.usePipes && c.usePty {
		if c.g != nil && c.g.Log != nil {
			c.g.Log.Warningf("options \"pipes\" and \"pty\" must not be specified together; ignoring \"pipes\"")
		}
		c.usePipes = false
	}

	// end-close is not pipes. Keep the default socketpair (and PTY when the
	// user asked for it). Shared LISTEN,fork reuse is serialized in
	// runForkListenRight (leftMu + sessionWrap) so a Close poke cannot leave
	// an expired deadline on the next accept. Do not switch transport here.

	// Reject after-socket options on user-selected pipes, pty, or nofork.
	// Socketpair (including end-close) applies those options on the child
	// endpoint instead of a silent no-op.
	if c.usePipes || c.usePty {
		if err := rejectUnusedExecPastSocketOptions(c.spec); err != nil {
			return err
		}
	}
	if err := c.wrapForkedFDHelper(ctx); err != nil {
		return err
	}
	return applyExecProcessAttrs(c.spec, c.cmd, c.g, c.fdRedirect)
}

func (c *execChild) startAndDropChildFDs(ctx context.Context, cleanup []func(), childFiles []*os.File) error {
	// Only FDs 0/1/2 may remain in the child.
	if err := startWithChildUmask(ctx, c.spec, c.cmd, c.g); err != nil {
		for _, f := range cleanup {
			f()
		}
		for _, child := range childFiles {
			logx.CloseQuiet(child)
		}
		return err
	}
	for _, child := range childFiles {
		logx.CloseQuiet(child)
	}
	return nil
}

func (c *execChild) startForked(ctx context.Context) (*Opened, error) {
	if c.usePty {
		return startCmdPty(ctx, c.spec, c.mode, c.g, c.cmd, c.fdRedirect)
	}

	// Child stderr inherits socat's stderr unless option stderr redirects it
	// onto the data channel. Merging stderr into the data FD corrupts binary
	// protocols (SOCKS4 echo scripts write diagnostics to stderr).
	if !c.spec.BoolOption("stderr") {
		c.cmd.Stderr = os.Stderr
	}

	var stream relay.Stream
	var cleanup []func()
	var childFiles []*os.File
	var err error
	if c.usePipes {
		stream, cleanup, childFiles, err = startCmdPipes(c.spec, c.mode, c.cmd, c.fdRedirect)
	} else {
		var child *os.File
		stream, cleanup, child, err = startCmdSocketpair(c.spec, c.mode, c.cmd, c.fdRedirect)
		if child != nil {
			childFiles = append(childFiles, child)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := c.startAndDropChildFDs(ctx, cleanup, childFiles); err != nil {
		return nil, err
	}
	return finishExec(c.spec, c.g, c.cmd, stream, cleanup, c.mode == ModeWrite, nil)
}

func startCmd(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	c, err := newExecChild(s, mode, g, cmd)
	if err != nil {
		return nil, err
	}
	// nofork: defer start until Run has the peer stream (runExecNoFork).
	// Placeholder Opened; Stream is nil — Run must not transferPair this alone.
	if s.BoolOption("nofork") {
		if err := rejectUnusedExecPastSocketOptions(s); err != nil {
			return nil, err
		}
		spec := s
		return &Opened{Kind: KindExec, Label: "EXEC-nofork", NoForkSpec: &spec}, nil
	}
	if err := c.prepareForked(ctx); err != nil {
		return nil, err
	}
	return c.startForked(ctx)
}

func validateProcessFDOptions(mode Mode, fdin, fdout string) error {
	if mode == ModeWrite && fdout != "" {
		return fmt.Errorf("fdout is not valid in a write-only process address")
	}
	if mode == ModeRead && fdin != "" {
		return fmt.Errorf("fdin is not valid in a read-only process address")
	}
	return nil
}

func processFDPair(s parse.Spec, mode Mode) (fdin, fdout string, err error) {
	fdin = s.OptionValue("fdin", "")
	fdout = s.OptionValue("fdout", "")
	if err = validateProcessFDOptions(mode, fdin, fdout); err != nil {
		return "", "", err
	}
	if fdin, err = normalizeProcessFD(fdin, "fdin"); err != nil {
		return "", "", err
	}
	if fdout, err = normalizeProcessFD(fdout, "fdout"); err != nil {
		return "", "", err
	}
	return fdin, fdout, nil
}

// dashFDRedirectMax is the largest descriptor dash (Ubuntu /bin/sh) accepts
// as a redirection prefix. Runtime mapping no longer uses that grammar;
// unusedFDNumbers still keeps historical prefix temps in 3–9.
const dashFDRedirectMax = 9

// fdin/fdout are unsigned short (0..65535). Overflow is rejected instead of
// wrapping onto an unrelated descriptor.
const maxProcessFD = 1<<16 - 1

func normalizeProcessFD(value, name string) (string, error) {
	if value == "" {
		return "", nil
	}
	n, err := ParseIntAny(value)
	if err != nil || n < 0 {
		return "", fmt.Errorf("%s: invalid file descriptor %q", name, value)
	}
	if n > maxProcessFD {
		return "", fmt.Errorf("%s: file descriptor %d exceeds unsigned-short range", name, n)
	}
	return strconv.Itoa(n), nil
}

func startCmdPipes(s parse.Spec, mode Mode, cmd *exec.Cmd, fdRedirect bool) (relay.Stream, []func(), []*os.File, error) {
	needIn, needOut := pipeDirections(mode)
	var stdin io.WriteCloser
	var stdout io.ReadCloser
	var parentFiles []*os.File
	var childFiles []*os.File
	closeFiles := func(files []*os.File) {
		for _, f := range files {
			_ = f.Close()
		}
	}

	if needIn {
		childStdin, parentStdin, err := os.Pipe()
		if err != nil {
			return nil, nil, nil, err
		}
		stdin = parentStdin
		childFiles = append(childFiles, childStdin)
		parentFiles = append(parentFiles, parentStdin)
		if err := ApplyFDOptions(childStdin, s); err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
	}
	if needOut {
		parentStdout, childStdout, err := os.Pipe()
		if err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
		stdout = parentStdout
		childFiles = append(childFiles, childStdout)
		parentFiles = append(parentFiles, parentStdout)
		if err := ApplyFDOptions(childStdout, s); err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
	}

	if fdRedirect {
		// The descriptor mapper expects ExtraFiles fd 3 (input) and fd 4
		// (output when both directions exist). Keep 0/1/2 inherited.
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = append([]*os.File(nil), childFiles...)
	} else {
		if needIn {
			cmd.Stdin = childFiles[0]
		} else {
			cmd.Stdin = os.Stdin
		}
		if needOut {
			out := childFiles[len(childFiles)-1]
			cmd.Stdout = out
			if s.BoolOption("stderr") {
				cmd.Stderr = out
			}
		} else {
			cmd.Stdout = os.Stdout
			if s.BoolOption("stderr") {
				cmd.Stderr = os.Stdout
			}
		}
	}

	var r io.Reader = stdout
	var w io.Writer = stdin
	if stdout == nil {
		r = EOFReader{}
	}
	if stdin == nil {
		w = io.Discard
	}
	st := relay.FDStream{
		R: r,
		W: w,
		C: NewMultiCloser(nil, nil),
		CloseW: func() error {
			if stdin != nil {
				return stdin.Close()
			}
			return nil
		},
	}
	cleanup := []func(){func() { closeFiles(parentFiles) }}
	return st, cleanup, childFiles, nil
}

func startCmdSocketpair(s parse.Spec, mode Mode, cmd *exec.Cmd, fdRedirect bool) (relay.Stream, []func(), *os.File, error) {
	stype, _, err := SocketTypeOption(s, syscall.SOCK_STREAM)
	if err != nil {
		return nil, nil, nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, stype, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	parent := os.NewFile(uintptr(fds[0]), "exec-parent")
	child := os.NewFile(uintptr(fds[1]), "exec-child")
	// After socket(), apply Spec.Options to the child endpoint only.
	// Standalone SOCKETPAIR still applies to both descriptors.
	if err := ApplySocketOptions(int(child.Fd()), s); err != nil {
		_ = parent.Close()
		_ = child.Close()
		return nil, nil, nil, err
	}
	if fdRedirect {
		// The descriptor mapper expects its socket at child fd 3. Keep 0/1/2
		// inherited until it duplicates fd 3 onto the
		// selected fdi/fdo descriptors (and stderr, when requested).
		cmd.ExtraFiles = []*os.File{child}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		// Unused stdio stays inherited so `socat -u EXEC:cat STDOUT` reads
		// process stdin and `socat -u STDIN EXEC:cat` writes process stdout.
		switch mode {
		case ModeWrite:
			cmd.Stdin = child
			cmd.Stdout = os.Stdout
			if s.BoolOption("stderr") {
				cmd.Stderr = os.Stdout
			}
		case ModeRead:
			cmd.Stdin = os.Stdin
			cmd.Stdout = child
			if s.BoolOption("stderr") {
				cmd.Stderr = child
			}
		default:
			cmd.Stdin = child
			cmd.Stdout = child
			if s.BoolOption("stderr") {
				cmd.Stderr = child
			}
		}
	}
	st := execSocketpairParentStream(mode, parent, stype)
	cleanup := []func(){func() {
		logx.CloseQuiet(parent)
	}}
	return st, cleanup, child, nil
}

func execSocketpairParentStream(mode Mode, parent *os.File, stype int) relay.Stream {
	switch mode {
	case ModeWrite:
		closeW := func() error { return shutdownWriteFile(parent) }
		if stype == syscall.SOCK_DGRAM {
			closeW = func() error {
				_, err := parent.Write(nil)
				return err
			}
		}
		return relay.FDStream{
			R:      EOFReader{},
			W:      parent,
			C:      NewMultiCloser(nil, nil),
			CloseW: closeW,
		}
	case ModeRead:
		return relay.FDStream{
			R:      parent,
			W:      io.Discard,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { return nil },
		}
	default:
		if stype == syscall.SOCK_DGRAM {
			return DgramPairStream(parent)
		}
		return FileStream(parent)
	}
}

// startWithChildUmask applies umask= around cmd.Start and marks FDs ≥3
// CLOEXEC so EXEC children inherit only 0/1/2 plus explicitly mapped fdi/fdo
// descriptors, then registers sighup/sigint/sigquit after pid is known.
func startWithChildUmask(ctx context.Context, s parse.Spec, cmd *exec.Cmd, g *Global) error {
	if err := validateExecParentSignals(s); err != nil {
		return err
	}
	armExecContextCancel(ctx, cmd)
	// Mark ALL FDs ≥3 CLOEXEC (including the socketpair/pipe/PTY ends passed
	// as Stdin/Stdout). Go's fork/exec dup2's them to 0/1/2 first, then closes
	// CLOEXEC descriptors, so the high-numbered originals are not leaked.
	setCloexecAllFrom(3)
	var startErr error
	if err := WithUmask(s, func() error {
		startErr = cmd.Start()
		return nil
	}); err != nil {
		forgetExecContextCancel(cmd)
		return err
	}
	if startErr != nil {
		forgetExecContextCancel(cmd)
		return startErr
	}
	if err := registerExecParentSignals(s, cmd, g); err != nil {
		killWaitUnregisterChild(cmd)
		return err
	}
	return nil
}

// killWaitUnregisterChild reaps a started EXEC child and drops signal
// registrations. Post-Start failures (PTY master lifecycle, SetupStream, too
// many pids) must not leave the pid in the four-slot tables: a later
// LISTEN,fork child can reuse the number and receive a stale kill.
func killWaitUnregisterChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		forgetExecContextCancel(cmd)
		return
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	unregisterChildSignals(pid)
	forgetExecContextCancel(cmd)
}

// execContextCancel disarms CommandContext's kill after end-close cleanup.
// cli.Run defers cancel(); without this, that cancel SIGKILLs children that
// end-close already chose to keep. Startup and in-flight cancel still kill.
type execContextCancel struct {
	ctx      context.Context
	mu       sync.Mutex
	released bool
}

var execContextCancels sync.Map // *exec.Cmd -> *execContextCancel

func contextCanceled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func armExecContextCancel(ctx context.Context, cmd *exec.Cmd) {
	if cmd == nil || cmd.Cancel == nil {
		return
	}
	ctl := &execContextCancel{ctx: ctx}
	prev := cmd.Cancel
	cmd.Cancel = func() error {
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		if ctl.released {
			return os.ErrProcessDone
		}
		return prev()
	}
	execContextCancels.Store(cmd, ctl)
}

func releaseExecContextCancel(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	v, ok := execContextCancels.Load(cmd)
	if !ok {
		return
	}
	ctl := v.(*execContextCancel)
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	// cancel() marks ctx done before CommandContext's callback runs. If that
	// already happened, keep the callback armed so it still kills.
	if contextCanceled(ctl.ctx) {
		return
	}
	ctl.released = true
	if contextCanceled(ctl.ctx) {
		ctl.released = false
	}
}

func forgetExecContextCancel(cmd *exec.Cmd) {
	if cmd != nil {
		execContextCancels.Delete(cmd)
	}
}

func setCloexecAllFrom(from int) {
	// Linux 5.11+: set CLOEXEC on the whole range in one call (covers sparse FDs
	// like cgroup handles that appear after /proc scans).
	if setCloexecRange(from) {
		return
	}
	// Fallback: snapshot /proc/self/fd then CloseOnExec each.
	f, err := os.Open("/proc/self/fd")
	if err == nil {
		names, _ := f.Readdirnames(-1)
		logx.CloseQuiet(f)
		for _, name := range names {
			fd, err := strconv.Atoi(name)
			if err != nil || fd < from {
				continue
			}
			CloseOnExec(fd)
		}
		return
	}
	for fd := from; fd < 1024; fd++ {
		CloseOnExec(fd)
	}
}

// execWaitState is the async Wait/reap for a forked EXEC child.
type execWaitState struct {
	done     chan struct{}
	mu       sync.Mutex
	waitErr  error
	exitCode int
}

func watchExecWait(cmd *exec.Cmd, done chan struct{}) *execWaitState {
	pid := 0
	if cmd != nil && cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	w := &execWaitState{done: done}
	if w.done == nil {
		w.done = make(chan struct{})
	}
	go func() {
		err := cmd.Wait()
		unregisterChildSignals(pid)
		forgetExecContextCancel(cmd)
		w.mu.Lock()
		w.waitErr = err
		if err == nil {
			w.exitCode = 0
		} else if ee, ok := err.(*exec.ExitError); ok {
			w.exitCode = ee.ExitCode()
		} else {
			w.exitCode = 1
		}
		w.mu.Unlock()
		close(w.done)
	}()
	return w
}

func (w *execWaitState) recordExit(g *Global) {
	w.mu.Lock()
	code := w.exitCode
	werr := w.waitErr
	w.mu.Unlock()
	if code != 0 && g != nil {
		if code < 0 || code >= 128 {
			return
		}
		g.ChildExitCode = code
		if werr != nil {
			g.ChildErr = werr
		}
	}
}

func (w *execWaitState) closeAfterTransfer(s parse.Spec, g *Global, cmd *exec.Cmd, waitChild bool, linger time.Duration, endClose bool) {
	if endClose {
		// Keep Wait reaping, but do not let later ctx cancel SIGKILL.
		releaseExecContextCancel(cmd)
		select {
		case <-w.done:
		default:
			return
		}
	} else {
		waitFor := linger
		if waitChild {
			waitFor = time.Second
		}
		if execUsesPTY(s) {
			waitFor = linger + time.Second
		}
		t := time.NewTimer(waitFor)
		select {
		case <-w.done:
			t.Stop()
		case <-t.C:
			_ = cmd.Process.Kill()
			<-w.done
		}
	}
	w.recordExit(g)
}

func finishExec(s parse.Spec, g *Global, cmd *exec.Cmd, stream relay.Stream, cleanup []func(), waitChild bool, done chan struct{}) (*Opened, error) {
	st, err := SetupStream(s, stream)
	if err != nil {
		killWaitUnregisterChild(cmd)
		for _, f := range cleanup {
			f()
		}
		return nil, err
	}

	w := watchExecWait(cmd, done)
	linger := 500 * time.Millisecond
	if g != nil && g.Linger > 0 {
		linger = g.Linger
	}
	endClose := s.BoolOption("end-close")
	o := &Opened{
		Stream:    st,
		Label:     "EXEC",
		childDone: w.done,
	}
	for _, f := range cleanup {
		o.AddCleanup(f)
	}
	o.AddCleanup(func() { w.closeAfterTransfer(s, g, cmd, waitChild, linger, endClose) })
	return o, nil
}

func pipeDirections(mode Mode) (needIn, needOut bool) {
	switch mode {
	case ModeRead:
		return false, true
	case ModeWrite:
		return true, false
	default:
		return true, true
	}
}
