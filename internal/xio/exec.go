//go:build unix

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
	hasCommand := len(s.Params) > 0 && s.Params[0] != ""
	return startCmd(ctx, s, mode, g, shellCommand(ctx, s, cmdStr, hasCommand))
}

// shellCommand matches classic SHELL: execl($SHELL, basename, [-c, command], NULL).
// nofork rebuilds the command in runExecNoFork, so this helper is the single
// place that honors shell= and $SHELL.
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
		// Split on whitespace for argv; classic EXEC uses simple space separation.
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	}
	return startCmd(ctx, s, mode, g, cmd)
}

// splitExecArgs splits an EXEC command line like classic nestlex/argv:
// unquoted runs of spaces separate args (no empty args from bare spaces);
// double-quoted segments keep spaces and may be empty ("" → empty arg);
// \" inside quotes is a literal quote (so -c 'echo "$1"' works).
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

// runExecNoFork runs EXEC/SYSTEM/SHELL with nofork on an already-open peer stream
// (classic: no relay — child inherits peer FDs as stdin/stdout).
// mode is the EXEC address mode: RDWR (echo), Write (-u right), Read (-u left).
func runExecNoFork(ctx context.Context, peer relay.Stream, s parse.Spec, g *Global, mode Mode) error {
	cmdStr := strings.Join(s.Params, ":")
	var cmd *exec.Cmd
	switch {
	case strings.EqualFold(s.Type, "SHELL"):
		hasCommand := len(s.Params) > 0 && s.Params[0] != ""
		cmd = shellCommand(ctx, s, cmdStr, hasCommand)
	case strings.EqualFold(s.Type, "SYSTEM"):
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	default:
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return fmt.Errorf("empty EXEC command")
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...) // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	}
	cmd.Dir = s.OptionValue("chdir", "")
	if s.BoolOption("setsid") {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
	}
	// Classic nofork FD wiring (xio-progcall !withfork):
	//   RDWR:  stdin=peer.R, stdout=peer.W  (STDIO: 0 and 1; socket: same FD twice)
	//   WRONLY (-u right EXEC): stdin=peer.R, stdout=process stdout (so echo appears)
	//   RDONLY (-u left EXEC):  stdin=process stdin, stdout=peer.W
	in, out, err := peerStdioFiles(peer, mode)
	if err != nil {
		return err
	}
	cmd.Stdin = in
	cmd.Stdout = out
	if s.BoolOption("stderr") {
		cmd.Stderr = out
	} else {
		cmd.Stderr = os.Stderr
	}
	if g != nil {
		cmd.Env = childEnviron(g)
	}
	if err := startWithChildUmask(s, cmd); err != nil {
		return err
	}
	waitErr := cmd.Wait()
	if waitErr == nil {
		return nil
	}
	if ee, ok := waitErr.(*exec.ExitError); ok {
		code := ee.ExitCode()
		if g != nil {
			g.ChildExitCode = code
		}
		// Signal deaths are reported via exit 128+n already by Wait on Unix.
		return nil
	}
	return waitErr
}

// peerStdioFiles returns child stdin/stdout Files for nofork, matching classic.
func peerStdioFiles(st relay.Stream, mode Mode) (in, out *os.File, err error) {
	r, w, single, err := streamRWFiles(st)
	if err != nil {
		return nil, nil, err
	}
	dup := func(f *os.File, name string) (*os.File, error) {
		if f == nil {
			return nil, fmt.Errorf("nofork: missing %s fd", name)
		}
		// os.Stdin/Stdout: ExtraFiles / Cmd will share; do not Dup and close.
		if f == os.Stdin || f == os.Stdout || f == os.Stderr {
			return f, nil
		}
		nfd, e := syscall.Dup(int(f.Fd()))
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(nfd), "nofork-"+name), nil
	}
	switch mode {
	case ModeWrite:
		// EXEC is write-only (right side of -u): child stdout stays process stdout.
		if single != nil {
			in, err = dup(single, "in")
		} else {
			in, err = dup(r, "in")
		}
		if err != nil {
			return nil, nil, err
		}
		return in, os.Stdout, nil
	case ModeRead:
		// EXEC is read-only (left side of -u): child stdin stays process stdin.
		if single != nil {
			out, err = dup(single, "out")
		} else {
			out, err = dup(w, "out")
		}
		if err != nil {
			return nil, nil, err
		}
		return os.Stdin, out, nil
	default:
		// Full duplex: STDIO uses 0+1; sockets use one duplex FD for both.
		if single != nil {
			in, err = dup(single, "in")
			if err != nil {
				return nil, nil, err
			}
			out, err = dup(single, "out")
			if err != nil {
				return nil, nil, err
			}
			return in, out, nil
		}
		in, err = dup(r, "in")
		if err != nil {
			return nil, nil, err
		}
		out, err = dup(w, "out")
		if err != nil {
			return nil, nil, err
		}
		return in, out, nil
	}
}

// streamRWFiles unwraps peer stream to read-file, write-file, and/or a single duplex FD.
func streamRWFiles(st relay.Stream) (r, w, single *os.File, err error) {
	for i := 0; i < 12 && st != nil; i++ {
		if ns, ok := st.(relay.NetStream); ok {
			if c, ok := ns.Conn.(interface {
				SyscallConn() (syscall.RawConn, error)
			}); ok {
				rc, e := c.SyscallConn()
				if e != nil {
					return nil, nil, nil, e
				}
				var ffd int
				_ = rc.Control(func(fd uintptr) { ffd = int(fd) })
				// Return the live conn fd; peerStdioFiles will Dup as needed.
				// We cannot return *os.File of the same fd without ownership issues;
				// Dup once here as single.
				nfd, e := syscall.Dup(ffd)
				if e != nil {
					return nil, nil, nil, e
				}
				return nil, nil, os.NewFile(uintptr(nfd), "nofork-conn"), nil
			}
		}
		if fs, ok := st.(relay.FDStream); ok {
			rf := asOSFile(fs.R)
			wf := asOSFile(fs.W)
			if rf != nil || wf != nil {
				return rf, wf, nil, nil
			}
		}
		if f, ok := st.(interface{ Fd() uintptr }); ok {
			nfd, e := syscall.Dup(int(f.Fd()))
			if e != nil {
				return nil, nil, nil, e
			}
			return nil, nil, os.NewFile(uintptr(nfd), "nofork-fd"), nil
		}
		if u, ok := st.(interface{ UnwrapStream() relay.Stream }); ok {
			st = u.UnwrapStream()
			continue
		}
		break
	}
	return nil, nil, nil, fmt.Errorf("nofork: peer stream has no file descriptor")
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
	if f, ok := x.(interface{ Fd() uintptr }); ok {
		// Do not wrap arbitrary Fd without knowing lifetime; only *os.File is safe.
		_ = f
	}
	return nil
}

func startCmd(ctx context.Context, s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	// nofork: defer start until Run has the peer stream (runExecNoFork).
	// Placeholder Opened; Stream is nil — Run must not transferPair this alone.
	if s.BoolOption("nofork") {
		spec := s
		return &Opened{Kind: KindExec, Label: "EXEC-nofork", NoForkSpec: &spec}, nil
	}
	cmd.Dir = s.OptionValue("chdir", "")
	// Default: socketpair for full duplex; pipes when requested or unidirectional
	// so unused direction can inherit process stdio (classic LISTENENV / single-exec).
	usePipes := s.BoolOption("pipes") || mode == ModeRead || mode == ModeWrite
	usePty := s.BoolOption("pty")

	// fdin/fdout: map socat's pipe ends onto child FDs via a shell exec redirect.
	fdin := s.OptionValue("fdin", "")
	fdout := s.OptionValue("fdout", "")
	if err := validateProcessFDOptions(mode, fdin, fdout); err != nil {
		return nil, err
	}
	var err error
	fdin, err = normalizeProcessFD(fdin, "fdin")
	if err != nil {
		return nil, err
	}
	fdout, err = normalizeProcessFD(fdout, "fdout")
	if err != nil {
		return nil, err
	}
	if fdin != "" || fdout != "" {
		usePipes = true
		usePty = false
		cmd = rebuildWithFDRedirect(ctx, cmd, fdin, fdout)
	}

	if s.BoolOption("setsid") {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
	}

	// Inject classic SOCAT_* connection environment for SYSTEM/EXEC children.
	if g != nil {
		cmd.Env = childEnviron(g)
	}

	if usePty {
		return startCmdPty(s, mode, g, cmd)
	}

	// end-close + shared LISTEN,fork: a single socketpair FD cannot be half-closed
	// per session and poll deadlines on the shared FD race with later accepts.
	// Separate pipes keep stdin/stdout independent (classic still works; our
	// goroutine accept model needs this for EXECENDCLOSE).
	if s.BoolOption("end-close") && !usePipes {
		usePipes = true
	}

	// Classic: child stderr inherits socat's stderr unless option stderr
	// redirects it onto the data channel. Merging stderr into the data FD
	// corrupts binary protocols (SOCKS4 echo scripts write diagnostics to stderr).
	if !s.BoolOption("stderr") {
		cmd.Stderr = os.Stderr
	}

	var stream relay.Stream
	var cleanup []func()
	var childFiles []*os.File
	if usePipes {
		stream, cleanup, childFiles, err = startCmdPipes(s, mode, cmd, fdin, fdout)
	} else {
		var child *os.File
		stream, cleanup, child, err = startCmdSocketpair(s, cmd)
		if child != nil {
			childFiles = append(childFiles, child)
		}
	}
	if err != nil {
		return nil, err
	}

	// EXEC_FDS: only FDs 0/1/2 may remain in the child.
	startErr := startWithChildUmask(s, cmd)
	if startErr != nil {
		for _, f := range cleanup {
			f()
		}
		for _, child := range childFiles {
			logx.CloseQuiet(child)
		}
		return nil, startErr
	}
	for _, child := range childFiles {
		logx.CloseQuiet(child)
	}

	return finishExec(s, g, cmd, stream, cleanup, mode == ModeWrite)
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

func normalizeProcessFD(value, name string) (string, error) {
	if value == "" {
		return "", nil
	}
	n, err := ParseIntAny(value)
	if err != nil || n < 0 {
		return "", fmt.Errorf("%s: invalid file descriptor %q", name, value)
	}
	return strconv.Itoa(n), nil
}

func startCmdPipes(s parse.Spec, mode Mode, cmd *exec.Cmd, fdin, fdout string) (relay.Stream, []func(), []*os.File, error) {
	needIn, needOut := pipeDirections(mode, fdin, fdout)
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
		cmd.Stdin = childStdin
		stdin = parentStdin
		childFiles = append(childFiles, childStdin)
		parentFiles = append(parentFiles, parentStdin)
		if err := ApplyFDOptions(childStdin, s); err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
	} else {
		cmd.Stdin = os.Stdin
	}
	if needOut {
		parentStdout, childStdout, err := os.Pipe()
		if err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
		cmd.Stdout = childStdout
		if s.BoolOption("stderr") {
			cmd.Stderr = childStdout
		}
		stdout = parentStdout
		childFiles = append(childFiles, childStdout)
		parentFiles = append(parentFiles, parentStdout)
		if err := ApplyFDOptions(childStdout, s); err != nil {
			closeFiles(parentFiles)
			closeFiles(childFiles)
			return nil, nil, nil, err
		}
	} else {
		cmd.Stdout = os.Stdout
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

func startCmdSocketpair(s parse.Spec, cmd *exec.Cmd) (relay.Stream, []func(), *os.File, error) {
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
	cmd.Stdin = child
	cmd.Stdout = child
	if s.BoolOption("stderr") {
		cmd.Stderr = child
	}
	var st relay.Stream
	if stype == syscall.SOCK_DGRAM {
		st = DgramPairStream(parent)
	} else {
		st = FileStream(parent)
	}
	cleanup := []func(){func() {
		logx.CloseQuiet(parent)
	}}
	return st, cleanup, child, nil
}

// startWithChildUmask applies classic umask= around cmd.Start and marks FDs ≥3
// CLOEXEC so EXEC children inherit only 0/1/2 (EXEC_FDS / EXEC_SNIFF).
func startWithChildUmask(s parse.Spec, cmd *exec.Cmd) error {
	// Mark ALL FDs ≥3 CLOEXEC (including the socketpair/pipe/PTY ends we pass
	// as Stdin/Stdout). Go's fork/exec dup2's them to 0/1/2 first, then closes
	// CLOEXEC descriptors, so the high-numbered originals are not leaked.
	setCloexecAllFrom(3)
	var startErr error
	if err := WithUmask(s, func() error {
		startErr = cmd.Start()
		return nil
	}); err != nil {
		return err
	}
	return startErr
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

// openExecPTYPair allocates a PTY pair for an EXEC child, applies the classic
// session/controlling-terminal attributes, and configures slave termios.
func openExecPTYPair(cmd *exec.Cmd, s parse.Spec) (*os.File, *os.File, error) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		return nil, nil, fmt.Errorf("EXEC pty: %w", err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = !s.HasOption("ctty") || s.BoolOption("ctty")
	if err := ApplyTermios(int(slave.Fd()), s); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	// Classic moves GROUP_NAMED perm/user/group to the PTY slave. Applying
	// them to the master changes the wrong descriptor and can fail differently
	// across platforms.
	if err := ApplyNamedAttrs(slave.Name(), s, slave); err != nil {
		logx.CloseQuiet(master)
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	return master, slave, nil
}

// closeExecPTY closes both PTY ends after a failed child start.
func closeExecPTY(master, slave *os.File) {
	logx.CloseQuiet(master)
	logx.CloseQuiet(slave)
}

// startCmdPty runs the child with a pseudo-terminal (classic EXEC/SYSTEM,pty).
//
// Unidirectional dual forms inherit the unused stdio of the socat process:
//
//	ModeWrite (-!!EXEC,pty): child stdin←PTY, child stdout→os.Stdout (inherit)
//	ModeRead  (EXEC,pty!!-): child stdin←os.Stdin (inherit), child stdout→PTY
//
// Full duplex: both directions on the PTY slave (startOnPTY).
func startCmdPty(s parse.Spec, mode Mode, g *Global, cmd *exec.Cmd) (*Opened, error) {
	var ptmx *os.File
	var err error

	switch mode {
	case ModeWrite:
		// Inherit stdout/stderr; only stdin is the PTY slave.
		master, slave, err := openExecPTYPair(cmd, s)
		if err != nil {
			return nil, err
		}
		ptmx = master
		cmd.Stdin = slave
		cmd.Stdout = os.Stdout
		if s.BoolOption("stderr") {
			cmd.Stderr = slave
		}
		if err := startWithChildUmask(s, cmd); err != nil {
			closeExecPTY(master, slave)
			return nil, err
		}
		logx.CloseQuiet(slave)
		if err := applyPtyMasterLifecycle(s, ptmx); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
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
		return finishExec(s, g, cmd, stream, []func(){func() { logx.CloseQuiet(ptmx) }}, true)

	case ModeRead:
		// Inherit stdin; only stdout/stderr on PTY slave.
		master, slave, err := openExecPTYPair(cmd, s)
		if err != nil {
			return nil, err
		}
		ptmx = master
		cmd.Stdin = os.Stdin
		cmd.Stdout = slave
		if s.BoolOption("stderr") {
			cmd.Stderr = slave
		}
		// Controlling tty is stdout/stderr slave; Setctty needs a child FD.
		// With stdin inherited, Ctty 1 (stdout) is the slave after setup.
		cmd.SysProcAttr.Ctty = 1
		if err := startWithChildUmask(s, cmd); err != nil {
			closeExecPTY(master, slave)
			return nil, err
		}
		logx.CloseQuiet(slave)
		if err := applyPtyMasterLifecycle(s, ptmx); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			logx.CloseQuiet(ptmx)
			return nil, err
		}
		stream := relay.FDStream{
			R:      ptmx,
			W:      io.Discard,
			C:      NewMultiCloser(nil, nil),
			CloseW: func() error { return nil },
		}
		return finishExec(s, g, cmd, stream, []func(){func() { logx.CloseQuiet(ptmx) }}, false)

	default:
		ptmx, err = startOnPTY(cmd, s)
		if err != nil {
			return nil, fmt.Errorf("EXEC pty: %w", err)
		}
		if err := applyPtyMasterLifecycle(s, ptmx); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			logx.CloseQuiet(ptmx)
			return nil, err
		}
		return finishExec(s, g, cmd, PtyExecStream(ptmx), []func(){func() { logx.CloseQuiet(ptmx) }}, false)
	}
}

func applyPtyOpts(s parse.Spec, ptmx *os.File) {
	_ = ApplyTermios(int(ptmx.Fd()), s)
}

func applyPtyMasterLifecycle(s parse.Spec, ptmx *os.File) error {
	applyPtyOpts(s, ptmx)
	return ApplyFDOptions(ptmx, s)
}

func finishExec(s parse.Spec, g *Global, cmd *exec.Cmd, stream relay.Stream, cleanup []func(), waitChild bool) (*Opened, error) {
	st, err := WrapCommon(s, stream)
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
	// Derived from the same ordered howtoshut selector as WrapCommon.
	shutNone := ShutNoneSelected(s)

	o := &Opened{
		Stream:    st,
		Label:     "EXEC",
		childDone: done,
	}
	for _, f := range cleanup {
		o.AddCleanup(f)
	}
	o.AddCleanup(func() {
		// Give write-only children (od -c) time to flush after stdin EOF.
		waitFor := linger
		if waitChild {
			// Classic xioshutdown(END_SHUTDOWN_KILL) on a write-only
			// EXEC/SHELL: Alarm(1); waitpid. Holds max-children slots
			// until the child finishes (POSIXMQ_RECV_MAXCHILDREN).
			waitFor = time.Second
		}
		if s.BoolOption("pty") {
			// Extra second so SYSTEM,pty scripts (RESTORE_TTY) can finish
			// after transfer linger, before we close the PTY master.
			waitFor = linger + time.Second
		}
		if shutNone {
			waitFor = 5 * time.Second
		}
		killed := false
		t := time.NewTimer(waitFor)
		select {
		case <-done:
			t.Stop()
		case <-t.C:
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
