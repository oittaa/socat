//go:build linux || darwin

package xio

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// runExecNoFork runs EXEC/SYSTEM/SHELL with nofork on an already-open peer
// stream (no relay — the command inherits the peer as its data descriptors).
// mode is the EXEC address mode: RDWR (echo), Write (-u right), Read (-u left).
// Default fdi/fdo are 0 and 1. Custom fdin/fdout reuse the forked child
// mapper: ExtraFiles sources plus Dup2 of WRFD onto fdo, then RDFD onto fdi,
// then stderr from fdo. Unrelated 0/1/2 stay inherited. Mapping runs in the
// child so a failed Start cannot leave the parent half-remapped.
// There is no transfer loop, so -D and -lm stay inactive.
//
// Phases: prepare command → attach peer (transfer FD ownership) → Start →
// drop ExtraFiles copies → Wait/reap.
func runExecNoFork(ctx context.Context, peer relay.Stream, s parse.Spec, config addrconfig.Address, g *Global, mode Mode) error {
	ctx = withPreparedConfig(ctx, config)
	cmd, err := commandForConfiguredExec(ctx, s, config)
	if err != nil {
		return err
	}
	if err := rejectUnusedExecPastSocketOptions(s); err != nil {
		return err
	}
	if err := rejectExecUnsupportedPTYOptions(s); err != nil {
		return err
	}
	c, err := newExecChild(ctx, s, mode, g, cmd)
	if err != nil {
		return err
	}
	return c.runNoFork(ctx, peer)
}

func commandForConfiguredExec(ctx context.Context, s parse.Spec, config addrconfig.Address) (*exec.Cmd, error) {
	cmdStr := strings.Join(s.Params, ":")
	switch {
	case strings.EqualFold(s.Type, "SHELL"):
		hasCommand := len(s.Params) > 0 && s.Params[0] != ""
		return configuredShellCommand(ctx, config.Process, cmdStr, hasCommand), nil
	case strings.EqualFold(s.Type, "SYSTEM"):
		return exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr), nil // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	default:
		parts := splitExecArgs(cmdStr)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty EXEC command")
		}
		return exec.CommandContext(ctx, parts[0], parts[1:]...), nil // #nosec G204 -- EXEC/SYSTEM/SHELL runs the command from the address line
	}
}

// wrapNoForkFDCommand applies the child dup2 helper to a nofork command.
// sameFD is a socket-like peer (one ExtraFiles source at fd 3); otherwise
// the peer is two pipes (fd 3 input, fd 4 output).
func wrapNoForkFDCommand(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	sameFD, withStderr bool,
) (*exec.Cmd, error) {
	if sameFD {
		return rebuildWithSocketFDHelper(ctx, cmd, mode, fdin, fdout, withStderr)
	}
	return rebuildWithPipeFDHelper(ctx, cmd, mode, fdin, fdout, withStderr)
}

// peerStdioFiles returns child stdin/stdout Files for nofork.
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

// noForkPeerExtraFiles dups the peer's data descriptors for ExtraFiles so
// fdin/fdout mapping can run in the child. sameFD is a socket-like peer
// (one ExtraFiles slot at child fd 3). Two distinct pipes use fd 3 (input)
// then fd 4 (output), matching extraSources. streamRWFiles may dup a conn
// into single; that copy is closed here after the ExtraFiles dup.
func noForkPeerExtraFiles(st relay.Stream, mode Mode) (files []*os.File, sameFD bool, err error) {
	r, w, single, err := streamRWFiles(st)
	if err != nil {
		return nil, false, err
	}
	owned := single
	defer func() {
		if owned != nil {
			logx.CloseQuiet(owned)
		}
	}()

	srcIn, srcOut := r, w
	if single != nil {
		srcIn, srcOut = single, single
		sameFD = true
	} else if r != nil && w != nil && r.Fd() == w.Fd() {
		srcOut = r
		sameFD = true
	}

	closeFiles := func() {
		for _, f := range files {
			logx.CloseQuiet(f)
		}
		files = nil
	}
	add := func(f *os.File, name string) error {
		d, err := dupNoForkExtra(f, name)
		if err != nil {
			closeFiles()
			return err
		}
		files = append(files, d)
		return nil
	}

	switch mode {
	case ModeWrite:
		if err := add(srcIn, "in"); err != nil {
			return nil, false, err
		}
		return files, false, nil
	case ModeRead:
		if err := add(srcOut, "out"); err != nil {
			return nil, false, err
		}
		return files, false, nil
	default:
		if sameFD {
			if err := add(srcIn, "rw"); err != nil {
				return nil, false, err
			}
			return files, true, nil
		}
		if err := add(srcIn, "in"); err != nil {
			return nil, false, err
		}
		if err := add(srcOut, "out"); err != nil {
			return nil, false, err
		}
		return files, false, nil
	}
}

func dupNoForkExtra(f *os.File, name string) (*os.File, error) {
	if f == nil {
		return nil, fmt.Errorf("nofork: missing %s fd", name)
	}
	nfd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	CloseOnExec(nfd)
	return os.NewFile(uintptr(nfd), "nofork-"+name), nil
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

func (c *execChild) attachNoForkStdio(peer relay.Stream, extra []*os.File) error {
	if c.fdRedirect {
		// Preserve unrelated 0/1/2; ExtraFiles become child fd 3+ and the
		// mapper Dup2's them onto fdi/fdo.
		c.cmd.Stdin = os.Stdin
		c.cmd.Stdout = os.Stdout
		c.cmd.Stderr = os.Stderr
		c.cmd.ExtraFiles = extra
		return nil
	}
	// nofork defaults (fdi=0, fdo=1):
	//   RDWR:  stdin=peer.R, stdout=peer.W  (STDIO: 0 and 1; socket: same FD twice)
	//   WRONLY (-u right EXEC): stdin=peer.R, stdout=process stdout (so echo appears)
	//   RDONLY (-u left EXEC):  stdin=process stdin, stdout=peer.W
	in, out, err := peerStdioFiles(peer, c.mode)
	if err != nil {
		return err
	}
	c.cmd.Stdin = in
	c.cmd.Stdout = out
	if c.config.Process.Stderr.Value {
		c.cmd.Stderr = out
	} else {
		c.cmd.Stderr = os.Stderr
	}
	return nil
}

func (c *execChild) waitNoFork() error {
	waitErr := c.cmd.Wait()
	if c.cmd.Process != nil {
		unregisterChildSignals(c.cmd.Process.Pid)
	}
	code, ok := childWaitExitCode(waitErr)
	if !ok {
		return waitErr
	}
	if c.g != nil {
		c.g.ChildExitCode = code
	}
	return nil
}

func (c *execChild) runNoFork(ctx context.Context, peer relay.Stream) error {
	var extra []*os.File
	closeExtra := func() {
		for _, f := range extra {
			logx.CloseQuiet(f)
		}
		extra = nil
	}
	defer closeExtra()

	if c.fdRedirect {
		var sameFD bool
		var err error
		extra, sameFD, err = noForkPeerExtraFiles(peer, c.mode)
		if err != nil {
			return err
		}
		if err := applyConfiguredDashArgv0(c.config.Process.Dash.Value, c.spec.Type, c.cmd); err != nil {
			return err
		}
		c.cmd, err = wrapNoForkFDCommand(ctx, c.cmd, c.mode, c.fdin, c.fdout, sameFD, c.config.Process.Stderr.Value)
		if err != nil {
			return err
		}
	}
	if err := applyExecProcessAttrs(c.spec, c.config, c.cmd, c.g, c.fdRedirect); err != nil {
		return err
	}
	if err := c.attachNoForkStdio(peer, extra); err != nil {
		return err
	}
	if err := c.start(ctx); err != nil {
		return err
	}
	closeExtra()
	return c.waitNoFork()
}
