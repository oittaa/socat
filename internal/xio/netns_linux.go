//go:build linux

package xio

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func init() {
	FeatureNAMESPACES = true
}

// netnsMu serializes setns around address open (fork uses goroutines).
var netnsMu sync.Mutex

// WithNetNS runs fn in Linux network namespace netns=NAME, then restores.
// The calling OS thread is locked for the whole section (setns is per-thread).
func WithNetNS(s parse.Spec, g *Global, fn func() error) error {
	name, ok := netnsName(s)
	if !ok {
		return fn()
	}
	warnNetNSExperimental(g)

	netnsMu.Lock()
	defer netnsMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const procNetNS = "/proc/self/ns/net"
	saved, err := unix.Open(procNetNS, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open(%s, O_RDONLY|O_CLOEXEC): %w", procNetNS, err)
	}
	defer func() { _ = unix.Close(saved) }()

	nspath := "/run/netns/" + name
	if g != nil && g.Log != nil {
		g.Log.Infof("switching to net namespace \"%s\"", name)
	}
	nsfd, err := unix.Open(nspath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open(%s, O_RDONLY|O_CLOEXEC): %w", nspath, err)
	}
	if err := unix.Setns(nsfd, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(nsfd)
		return fmt.Errorf("setns(%d, CLONE_NEWNET): %w", nsfd, err)
	}
	_ = unix.Close(nsfd)

	fnErr := fn()
	if err := unix.Setns(saved, unix.CLONE_NEWNET); err != nil {
		if fnErr == nil {
			return fmt.Errorf("setns(%d, CLONE_NEWNET): %w", saved, err)
		}
	}
	return fnErr
}
