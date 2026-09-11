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

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func openEXEC(ctx context.Context, s addrconfig.Address, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("EXEC requires command")
	}
	// Spaces separate argv; the address parser may have split on ':' so rejoin.
	// Quoted commands land as a single param (e.g. EXEC:"ls -l").
	cmdStr := strings.Join(s.Params, ":")
	return startProcess(ctx, s, mode, g, cmdStr, false)
}

func openSYSTEM(ctx context.Context, s addrconfig.Address, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("SYSTEM requires command")
	}
	cmdStr := strings.Join(s.Params, ":")
	return startProcess(ctx, s, mode, g, cmdStr, true)
}

func openSHELL(ctx context.Context, s addrconfig.Address, mode Mode, g *Global) (*Opened, error) {
	cmdStr := strings.Join(s.Params, ":")
	hasCommand := len(s.Params) > 0 && s.Params[0] != ""
	return startCmd(ctx, s, mode, g, configuredShellCommand(ctx, s.Process, cmdStr, hasCommand))
}

func configuredShellCommand(ctx context.Context, config addrconfig.Process, cmdStr string, hasCommand bool) *exec.Cmd {
	shell := config.Shell.Value
	if !config.Shell.Set || shell == "" {
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

func startProcess(ctx context.Context, s addrconfig.Address, mode Mode, g *Global, cmdStr string, useShell bool) (*Opened, error) {
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

func applyConfiguredExecChildOptions(config addrconfig.Process, addressType string, cmd *exec.Cmd) error {
	if err := applyConfiguredDashArgv0(config.Dash.Value, addressType, cmd); err != nil {
		return err
	}
	return applyConfiguredSetpgid(config.SetPGID, cmd)
}

func applyConfiguredDashArgv0(enabled bool, addressType string, cmd *exec.Cmd) error {
	if !enabled {
		return nil
	}
	if !strings.EqualFold(addressType, "EXEC") {
		return fmt.Errorf("dash: unused on %s", addressType)
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

func applyConfiguredSetpgid(value addrconfig.OptionalInt, cmd *exec.Cmd) error {
	if !value.Set {
		return nil
	}
	pgid := value.Value
	if pgid == 0 || pgid == 1 {
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

// childWaitExitCode maps cmd.Wait to a process exit status. Go's
// exec.ExitError.ExitCode is -1 when the child was signaled; POSIX shells
// report 128+signum. Forked EXEC still skips those statuses on close so a
// PTY-master SIGHUP does not become EXEC_RC.
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
func rejectUnusedExecPastSocketOptions(config addrconfig.Address) error {
	for _, action := range config.Network.Actions {
		if name, ok := unusedExecPastSocketName(action); ok {
			return fmt.Errorf("option %q not inquired", name)
		}
	}
	return nil
}

func unusedExecPastSocketName(action addrconfig.SocketAction) (string, bool) {
	switch action.Kind {
	case addrconfig.SocketActionBroadcast:
		return "broadcast", true
	case addrconfig.SocketActionBindToDevice:
		return "bindtodevice", true
	case addrconfig.SocketActionLinger:
		return "so-linger", true
	case addrconfig.SocketActionTimeout:
		if action.Text != "" {
			return action.Text, true
		}
		return "rcvtimeo", true
	case addrconfig.SocketActionBuffer:
		if action.Phase == addrconfig.SocketPhasePastSocket && action.Text != "" {
			return action.Text, true
		}
	case addrconfig.SocketActionNamed:
		if action.Phase == addrconfig.SocketPhasePastSocket {
			if action.Text != "" {
				return action.Text, true
			}
		}
	case addrconfig.SocketActionGeneric:
		if action.Phase == addrconfig.SocketPhasePastSocket {
			name := action.Text
			if name == "" {
				name = "setsockopt-socket"
			}
			return name, true
		}
	}
	return "", false
}

// execChild is one EXEC/SYSTEM/SHELL start after argv exists.
// It owns the command, CommandContext cancel disarm, and Wait/reap.
// Forked: prepare → open transport FDs → Start → drop child-side FDs → finish.
// nofork: prepare → attach peer as stdio → Start → drop ExtraFiles → Wait.
type execChild struct {
	config     addrconfig.Address
	mode       Mode
	g          *Global
	cmd        *exec.Cmd
	fdin       string
	fdout      string
	fdRedirect bool
	usePipes   bool
	usePty     bool
	cancel     *execContextCancel // armed at start; stays until the owner is dropped
	wait       *execWaitState
}

func newExecChild(ctx context.Context, s addrconfig.Address, mode Mode, g *Global, cmd *exec.Cmd) (*execChild, error) {
	fdin, fdout, err := processFDPairConfig(s.Process, mode)
	if err != nil {
		return nil, err
	}
	return &execChild{
		config:     s,
		mode:       mode,
		g:          g,
		cmd:        cmd,
		fdin:       fdin,
		fdout:      fdout,
		fdRedirect: fdin != "" || fdout != "",
	}, nil
}

// applyExecProcessAttrs sets chdir, setsid, dash/setpgid, and SOCAT_* env.
func applyExecProcessAttrs(config addrconfig.Address, cmd *exec.Cmd, g *Global, fdRedirect bool) error {
	if config.Process.Chdir.Set {
		cmd.Dir = config.Process.Chdir.Value
	}
	if config.Process.SetSID.Value {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
	}
	if fdRedirect {
		if err := applyConfiguredSetpgid(config.Process.SetPGID, cmd); err != nil {
			return err
		}
	} else if err := applyConfiguredExecChildOptions(config.Process, config.Type, cmd); err != nil {
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
	if err := applyConfiguredDashArgv0(c.config.Process.Dash.Value, c.config.Type, c.cmd); err != nil {
		return err
	}
	var err error
	if c.usePipes {
		c.cmd, err = rebuildWithPipeFDHelper(ctx, c.cmd, c.mode, c.fdin, c.fdout, c.config.Process.Stderr.Value)
	} else {
		// Socketpair and PTY share ExtraFiles[0] (child fd 3).
		c.cmd, err = rebuildWithSocketFDHelper(ctx, c.cmd, c.mode, c.fdin, c.fdout, c.config.Process.Stderr.Value)
	}
	return err
}

func (c *execChild) prepareForked(ctx context.Context) error {
	if err := rejectExecUnsupportedPTYOptions(c.config); err != nil {
		return err
	}
	userPipes := c.config.Process.Pipes.Value
	c.usePty = c.config.Process.PTY.Value
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
		if err := rejectUnusedExecPastSocketOptions(c.config); err != nil {
			return err
		}
	}
	if err := c.wrapForkedFDHelper(ctx); err != nil {
		return err
	}
	return applyExecProcessAttrs(c.config, c.cmd, c.g, c.fdRedirect)
}

func (c *execChild) startAndDropChildFDs(ctx context.Context, cleanup []func(), childFiles []*os.File) error {
	// Only FDs 0/1/2 may remain in the child.
	if err := c.start(ctx); err != nil {
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
		return c.startPty(ctx)
	}

	// Child stderr inherits socat's stderr unless option stderr redirects it
	// onto the data channel. Merging stderr into the data FD corrupts binary
	// protocols (SOCKS4 echo scripts write diagnostics to stderr).
	if !c.config.Process.Stderr.Value {
		c.cmd.Stderr = os.Stderr
	}

	var stream relay.Stream
	var cleanup []func()
	var childFiles []*os.File
	var err error
	if c.usePipes {
		stream, cleanup, childFiles, err = startCmdPipes(c.config, c.mode, c.cmd, c.fdRedirect)
	} else {
		var child *os.File
		stream, cleanup, child, err = startCmdSocketpair(c.config, c.mode, c.cmd, c.fdRedirect)
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
	return c.finish(stream, cleanup, c.mode == ModeWrite, nil)
}

func startCmd(ctx context.Context, s addrconfig.Address, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	c, err := newExecChild(ctx, s, mode, g, cmd)
	if err != nil {
		return nil, err
	}
	// nofork: defer start until Run has the peer stream (runExecNoFork).
	// Placeholder Opened; Stream is nil — Run must not transferPair this alone.
	if c.config.Common.NoFork.Value {
		if err := rejectUnusedExecPastSocketOptions(c.config); err != nil {
			return nil, err
		}
		config := c.config
		return &Opened{Kind: KindExec, Label: "EXEC-nofork", NoForkConfig: &config}, nil
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

func processFDPairConfig(config addrconfig.Process, mode Mode) (fdin, fdout string, err error) {
	if config.FDIn.Set {
		fdin = strconv.Itoa(config.FDIn.Value)
	}
	if config.FDOut.Set {
		fdout = strconv.Itoa(config.FDOut.Value)
	}
	if err = validateProcessFDOptions(mode, fdin, fdout); err != nil {
		return "", "", err
	}
	return fdin, fdout, nil
}

// dashFDRedirectMax is the largest descriptor dash (Ubuntu /bin/sh) accepts
// as a redirection prefix. Runtime mapping no longer uses that grammar;
// unusedFDNumbers still keeps historical prefix temps in 3–9.
const dashFDRedirectMax = 9

func startCmdPipes(config addrconfig.Address, mode Mode, cmd *exec.Cmd, fdRedirect bool) (relay.Stream, []func(), []*os.File, error) {
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
		if err := ApplyConfiguredFDOptions(childStdin, config.File, FDSkip{}); err != nil {
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
		if err := ApplyConfiguredFDOptions(childStdout, config.File, FDSkip{}); err != nil {
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
			if config.Process.Stderr.Value {
				cmd.Stderr = out
			}
		} else {
			cmd.Stdout = os.Stdout
			if config.Process.Stderr.Value {
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

func startCmdSocketpair(config addrconfig.Address, mode Mode, cmd *exec.Cmd, fdRedirect bool) (relay.Stream, []func(), *os.File, error) {
	stype, _, err := SocketTypeOption(config, syscall.SOCK_STREAM)
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
	if err := ApplySocketOptions(int(child.Fd()), config); err != nil {
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
			if config.Process.Stderr.Value {
				cmd.Stderr = os.Stdout
			}
		case ModeRead:
			cmd.Stdin = os.Stdin
			cmd.Stdout = child
			if config.Process.Stderr.Value {
				cmd.Stderr = child
			}
		default:
			cmd.Stdin = child
			cmd.Stdout = child
			if config.Process.Stderr.Value {
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

// start applies umask= around cmd.Start and marks FDs ≥3 CLOEXEC so EXEC
// children inherit only 0/1/2 plus explicitly mapped fdi/fdo descriptors,
// then registers sighup/sigint/sigquit after pid is known.
func (c *execChild) start(ctx context.Context) error {
	c.armCancel(ctx)
	// Mark ALL FDs ≥3 CLOEXEC (including the socketpair/pipe/PTY ends passed
	// as Stdin/Stdout). Go's fork/exec dup2's them to 0/1/2 first, then closes
	// CLOEXEC descriptors, so the high-numbered originals are not leaked.
	setCloexecAllFrom(3)
	var startErr error
	if err := WithConfiguredUmask(c.config.File, func() error {
		startErr = c.cmd.Start()
		return nil
	}); err != nil {
		return err
	}
	if startErr != nil {
		return startErr
	}
	if err := registerExecParentSignals(c.config, c.cmd, c.g); err != nil {
		c.killWait()
		return err
	}
	return nil
}

// killWait reaps a started EXEC child and drops signal registrations. Post-Start
// failures (PTY master lifecycle, SetupStream, too many pids) must not leave
// the pid in the four-slot tables: a later LISTEN,fork child can reuse the
// number and receive a stale kill.
func (c *execChild) killWait() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	pid := c.cmd.Process.Pid
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
	unregisterChildSignals(pid)
}

// execContextCancel disarms CommandContext's kill after end-close cleanup.
// cli.Run defers cancel(); without this, that cancel SIGKILLs children that
// end-close already chose to keep. Startup and in-flight cancel still kill.
type execContextCancel struct {
	ctx      context.Context
	mu       sync.Mutex
	released bool
}

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

func (c *execChild) armCancel(ctx context.Context) {
	if c == nil || c.cmd == nil || c.cmd.Cancel == nil {
		return
	}
	ctl := &execContextCancel{ctx: ctx}
	prev := c.cmd.Cancel
	c.cmd.Cancel = func() error {
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		if ctl.released {
			return os.ErrProcessDone
		}
		return prev()
	}
	c.cancel = ctl
}

func (c *execChild) releaseCancel() {
	if c == nil || c.cancel == nil {
		return
	}
	ctl := c.cancel
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

func (c *execChild) watchWait(done chan struct{}) *execWaitState {
	pid := 0
	if c.cmd != nil && c.cmd.Process != nil {
		pid = c.cmd.Process.Pid
	}
	w := &execWaitState{done: done}
	if w.done == nil {
		w.done = make(chan struct{})
	}
	go func() {
		err := c.cmd.Wait()
		unregisterChildSignals(pid)
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
	c.wait = w
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

func (c *execChild) closeAfterTransfer(waitChild bool, linger time.Duration, endClose bool) {
	w := c.wait
	if w == nil {
		return
	}
	if endClose {
		// Keep Wait reaping, but do not let later ctx cancel SIGKILL.
		c.releaseCancel()
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
		if c.config.Process.PTY.Value {
			waitFor = linger + time.Second
		}
		t := time.NewTimer(waitFor)
		select {
		case <-w.done:
			t.Stop()
		case <-t.C:
			_ = c.cmd.Process.Kill()
			<-w.done
		}
	}
	w.recordExit(c.g)
}

func (c *execChild) finish(stream relay.Stream, cleanup []func(), waitChild bool, done chan struct{}) (*Opened, error) {
	return c.finishStream(stream, cleanup, waitChild, done, SetupStream)
}

func (c *execChild) finishAfterFD(stream relay.Stream, cleanup []func(), waitChild bool, done chan struct{}) (*Opened, error) {
	return c.finishStream(stream, cleanup, waitChild, done, WrapAfterFD)
}

func (c *execChild) finishStream(stream relay.Stream, cleanup []func(), waitChild bool, done chan struct{}, wrap func(addrconfig.Address, relay.Stream) (relay.Stream, error)) (*Opened, error) {
	st, err := wrap(c.config, stream)
	if err != nil {
		c.killWait()
		for _, f := range cleanup {
			f()
		}
		return nil, err
	}

	w := c.watchWait(done)
	linger := 500 * time.Millisecond
	if c.g != nil && c.g.Linger > 0 {
		linger = c.g.Linger
	}
	endClose := c.config.Transfer.EndClose.Value
	o := &Opened{
		Stream:    st,
		Label:     "EXEC",
		childDone: w.done,
	}
	for _, f := range cleanup {
		o.AddCleanup(f)
	}
	o.AddCleanup(func() { c.closeAfterTransfer(waitChild, linger, endClose) })
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
