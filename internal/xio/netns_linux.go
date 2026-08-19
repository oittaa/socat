//go:build linux

package xio

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

var setnsFunc = unix.Setns

func init() {
	FeatureNAMESPACES = true
}

// WithNetNS runs fn in Linux network namespace netns=NAME, then restores.
// The calling OS thread is locked for the whole section (setns is per-thread).
// There is no process-wide mutex: setns is per-thread, and a lock here
// deadlocks LISTEN,netns= (Accept) against a same-process CONNECT,netns=.
func WithNetNS(s parse.Spec, g *Global, fn func() error) (err error) {
	name, ok := netnsName(s)
	if !ok {
		return fn()
	}
	warnNetNSExperimental(g)

	runtime.LockOSThread()
	// A goroutine that exits while locked causes the runtime to discard its OS
	// thread. Only unlock when we know the original namespace was restored.
	safeToReuse := true
	defer func() {
		if safeToReuse {
			runtime.UnlockOSThread()
		}
	}()

	const procNetNS = "/proc/self/ns/net"
	saved, err := unix.Open(procNetNS, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open(%s, O_RDONLY|O_CLOEXEC): %w", procNetNS, err)
	}

	nspath := "/run/netns/" + name
	if g != nil && g.Log != nil {
		g.Log.Infof("switching to net namespace \"%s\"", name)
	}
	nsfd, err := unix.Open(nspath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(saved)
		return fmt.Errorf("open(%s, O_RDONLY|O_CLOEXEC): %w", nspath, err)
	}
	if err := setnsFunc(nsfd, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(nsfd)
		_ = unix.Close(saved)
		return fmt.Errorf("setns(%d, CLONE_NEWNET): %w", nsfd, err)
	}
	_ = unix.Close(nsfd)
	safeToReuse = false

	defer func() { _ = unix.Close(saved) }()
	return runAndRestoreNetNS(saved, &safeToReuse, fn)
}

// runAndRestoreNetNS gives the restore error a named return path. It also runs
// during panic unwinding; safeToReuse stays false if restoration fails so the
// runtime cannot schedule unrelated goroutines on the contaminated OS thread.
func runAndRestoreNetNS(saved int, safeToReuse *bool, fn func() error) (err error) {
	defer func() {
		if restoreErr := setnsFunc(saved, unix.CLONE_NEWNET); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("setns(%d, CLONE_NEWNET): %w", saved, restoreErr))
			return
		}
		*safeToReuse = true
	}()
	return fn()
}
