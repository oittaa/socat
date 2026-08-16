//go:build linux

package xio

import (
	"fmt"
	"runtime"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func init() {
	FeatureNAMESPACES = true
}

// WithNetNS runs fn in Linux network namespace netns=NAME, then restores.
// The calling OS thread is locked for the whole section (setns is per-thread).
// There is no process-wide mutex: setns is per-thread, and a lock here
// deadlocks LISTEN,netns= (Accept) against a same-process CONNECT,netns=.
func WithNetNS(s parse.Spec, g *Global, fn func() error) error {
	name, ok := netnsName(s)
	if !ok {
		return fn()
	}
	warnNetNSExperimental(g)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
	if err := unix.Setns(nsfd, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(nsfd)
		_ = unix.Close(saved)
		return fmt.Errorf("setns(%d, CLONE_NEWNET): %w", nsfd, err)
	}
	_ = unix.Close(nsfd)

	// Restore even if fn panics so this OS thread is not returned to the
	// runtime still attached to the target namespace.
	var fnErr error
	defer func() {
		if e := unix.Setns(saved, unix.CLONE_NEWNET); e != nil && fnErr == nil {
			fnErr = fmt.Errorf("setns(%d, CLONE_NEWNET): %w", saved, e)
		}
		_ = unix.Close(saved)
	}()
	fnErr = fn()
	return fnErr
}
