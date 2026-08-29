//go:build linux || darwin

package xio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// execFDHelperMarker selects the child-only descriptor remapper. Custom
// fdin/fdout always remap in the child so dup2 never mutates socat's table,
// bare SHELL keeps its argv, and dash/login rewrite the target argv[0]
// rather than a /bin/sh wrapper. The parent adds a private environment
// handshake; the helper removes it before exec.
const (
	execFDHelperMarker = "--socat-internal-exec-fd-helper"
	execFDHelperEnv    = "SOCAT_INTERNAL_EXEC_FD_HELPER"
)

func init() {
	// The argv marker alone is intentionally insufficient: xio is a library
	// package, so importing it must not turn an ordinary public argument into
	// an init-time process takeover.
	if len(os.Args) < 2 || os.Args[1] != execFDHelperMarker || os.Getenv(execFDHelperEnv) != "1" {
		return
	}
	if err := runExecFDHelper(os.Args[2:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "socat exec fd helper: %v\n", err)
		var te *execTargetError
		if errors.As(err, &te) {
			// unix.Exec failed: exit 1. A target that itself exits 127
			// still reports 127 because unix.Exec replaced the helper.
			os.Exit(1)
		}
		os.Exit(127)
	}
	os.Exit(127)
}

func rebuildWithSocketFDHelper(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	withStderr bool,
) (*exec.Cmd, error) {
	inSrc, outSrc := extraSources(mode, true)
	return rebuildWithFDHelper(ctx, cmd, inSrc, outSrc, fdin, fdout, withStderr)
}

func rebuildWithPipeFDHelper(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	withStderr bool,
) (*exec.Cmd, error) {
	inSrc, outSrc := extraSources(mode, false)
	return rebuildWithFDHelper(ctx, cmd, inSrc, outSrc, fdin, fdout, withStderr)
}

func rebuildWithFDHelper(
	ctx context.Context,
	cmd *exec.Cmd,
	inSrc, outSrc, fdin, fdout string,
	withStderr bool,
) (*exec.Cmd, error) {
	if cmd == nil || len(cmd.Args) == 0 {
		return nil, fmt.Errorf("exec fd helper: missing target command")
	}
	// LookPath failure is reported by the helper's unix.Exec as missing
	// PATH → exit 1. Other Command errors (bad Path, etc.) stay here.
	if cmd.Err != nil && !errors.Is(cmd.Err, exec.ErrNotFound) {
		return nil, cmd.Err
	}
	helperPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("exec fd helper: locate socat executable: %w", err)
	}

	inTarget, outTarget := "-1", "-1"
	if inSrc != "" {
		inTarget = defaultFDI(fdin)
	}
	if outSrc != "" {
		outTarget = defaultFDO(fdout)
	}
	if inSrc == "" {
		inSrc = "-1"
	}
	if outSrc == "" {
		outSrc = "-1"
	}
	stderrFlag := "0"
	if withStderr {
		stderrFlag = "1"
	}

	args := []string{
		execFDHelperMarker,
		inSrc,
		outSrc,
		inTarget,
		outTarget,
		stderrFlag,
		resolvedExecPath(cmd),
		cmd.Args[0],
	}
	args = append(args, cmd.Args[1:]...)
	return exec.CommandContext(ctx, helperPath, args...), nil // #nosec G204 -- helper path is the current executable; target is the user-requested EXEC/SYSTEM command
}

func resolvedExecPath(cmd *exec.Cmd) string {
	if cmd == nil {
		return ""
	}
	path := cmd.Path
	if path == "" || filepath.Base(path) != path {
		return path
	}
	lp, err := exec.LookPath(path)
	if err != nil {
		// Leave the basename so unix.Exec fails like a missing PATH entry.
		return path
	}
	return lp
}

type execTargetError struct {
	path  string
	argv0 string
	err   error
}

func (e *execTargetError) Error() string {
	if e == nil {
		return "execvp failed"
	}
	argv0 := e.argv0
	if argv0 == "" {
		argv0 = e.path
	}
	return fmt.Sprintf("execvp(\"%s\", \"%s\"): %v", e.path, argv0, e.err)
}

func (e *execTargetError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func runExecFDHelper(args []string) error {
	if len(args) < 7 {
		return fmt.Errorf("invalid helper arguments")
	}
	values := make([]int, 5)
	for i := range values {
		n, err := strconv.Atoi(args[i])
		if err != nil {
			return fmt.Errorf("invalid descriptor %q", args[i])
		}
		values[i] = n
	}
	if values[4] != 0 && values[4] != 1 {
		return fmt.Errorf("invalid stderr flag %d", values[4])
	}
	targetPath := args[5]
	targetArgv := args[6:]
	if targetPath == "" || len(targetArgv) == 0 {
		return fmt.Errorf("missing target command")
	}
	if err := remapExecFDs(values[0], values[1], values[2], values[3], values[4] == 1); err != nil {
		return err
	}
	err := unix.Exec(targetPath, targetArgv, withoutExecFDHelperEnv(os.Environ()))
	if err != nil {
		return &execTargetError{path: targetPath, argv0: targetArgv[0], err: err}
	}
	return nil
}

func withExecFDHelperEnv(env []string) []string {
	if env == nil {
		env = os.Environ()
	}
	env = withoutExecFDHelperEnv(env)
	return append(env, execFDHelperEnv+"=1")
}

func withoutExecFDHelperEnv(env []string) []string {
	prefix := execFDHelperEnv + "="
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

type execFDMove struct {
	source int
	target int
}

// remapExecFDs duplicates the output endpoint first, then the input
// endpoint, optionally duplicates fdo onto stderr, and closes child-side
// source descriptors that are not final targets. When fdin == fdout on
// full-duplex pipes, the input mapping wins. Socketpair and PTY use one
// source for both directions. Sources are copied before applying any move
// so swaps such as 3->4 and 4->3 are safe.
func remapExecFDs(inSrc, outSrc, inTarget, outTarget int, withStderr bool) error {
	moves := make([]execFDMove, 0, 2)
	if outSrc >= 0 {
		moves = append(moves, execFDMove{source: outSrc, target: outTarget})
	}
	if inSrc >= 0 {
		moves = append(moves, execFDMove{source: inSrc, target: inTarget})
	}
	for _, move := range moves {
		if move.target < 0 {
			return fmt.Errorf("invalid target descriptor %d", move.target)
		}
	}

	reserved := map[int]bool{0: true, 1: true, 2: true}
	for _, move := range moves {
		reserved[move.source] = true
		reserved[move.target] = true
	}
	temps := make(map[int]int, len(moves))
	for _, move := range moves {
		if _, ok := temps[move.source]; ok {
			continue
		}
		temp, err := dupExecFDOutside(move.source, reserved)
		if err != nil {
			return fmt.Errorf("duplicate source fd %d: %w", move.source, err)
		}
		temps[move.source] = temp
		reserved[temp] = true
	}
	defer func() {
		for _, temp := range temps {
			_ = unix.Close(temp)
		}
	}()

	for _, move := range moves {
		if err := unix.Dup2(temps[move.source], move.target); err != nil {
			return fmt.Errorf("dup2(%d, %d): %w", move.source, move.target, err)
		}
	}
	if withStderr {
		stderrSource := 1
		if outSrc >= 0 {
			stderrSource = outTarget
		}
		if err := unix.Dup2(stderrSource, 2); err != nil {
			return fmt.Errorf("dup2(%d, 2): %w", stderrSource, err)
		}
	}

	finalTargets := make(map[int]bool, len(moves))
	for _, move := range moves {
		finalTargets[move.target] = true
	}
	closed := map[int]bool{}
	for _, move := range moves {
		if finalTargets[move.source] || closed[move.source] {
			continue
		}
		if err := unix.Close(move.source); err != nil {
			return fmt.Errorf("close source fd %d: %w", move.source, err)
		}
		closed[move.source] = true
	}
	return nil
}

// dupExecFDOutside creates a temporary copy that cannot collide with a source,
// target, or standard descriptor. Conflicting low-numbered duplicates are held
// open until a safe number is allocated, then closed.
func dupExecFDOutside(fd int, reserved map[int]bool) (int, error) {
	var held []int
	defer func() {
		for _, n := range held {
			_ = unix.Close(n)
		}
	}()
	for {
		n, err := unix.Dup(fd)
		if err != nil {
			return -1, err
		}
		if reserved[n] {
			held = append(held, n)
			continue
		}
		unix.CloseOnExec(n)
		return n, nil
	}
}
