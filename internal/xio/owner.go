package xio

import (
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"sync"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyOwner applies classic user= / group= via chown/fchown after create/bind.
// Empty options are no-ops. Numeric and name forms are accepted.
func ApplyOwner(path string, s parse.Spec, f *os.File) error {
	uid, hasU, err := resolveUID(s.OptionValue("user", ""))
	if err != nil {
		return err
	}
	gid, hasG, err := resolveGID(s.OptionValue("group", ""))
	if err != nil {
		return err
	}
	if !hasU && !hasG {
		return nil
	}
	// Linux: -1 leaves that id unchanged.
	u, g := -1, -1
	if hasU {
		u = uid
	}
	if hasG {
		g = gid
	}
	if f != nil {
		if err := f.Chown(u, g); err != nil {
			if path != "" {
				if e2 := os.Chown(path, u, g); e2 != nil {
					return fmt.Errorf("chown %s: %w", path, err)
				}
				return nil
			}
			return fmt.Errorf("fchown: %w", err)
		}
		return nil
	}
	if path == "" {
		return nil
	}
	if err := os.Chown(path, u, g); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

func resolveUID(name string) (int, bool, error) {
	if name == "" {
		return -1, false, nil
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n, true, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return -1, false, fmt.Errorf("user %q: %w", name, err)
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, false, err
	}
	return n, true, nil
}

func resolveGID(name string) (int, bool, error) {
	if name == "" {
		return -1, false, nil
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n, true, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, false, fmt.Errorf("group %q: %w", name, err)
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, false, err
	}
	return n, true, nil
}

// --- path unlink registry: classic removes named FS entries on process exit ---

var (
	unlinkMu    sync.Mutex
	unlinkPaths []string
	exitHooks   []func()
)

// RegisterUnlinkPath records a filesystem path to remove on process signal exit
// (SIGTERM etc.). Classic xio_close unlinks; our signal path uses os.Exit and
// would otherwise leave UNIX/PIPE/PTY link entries (REMOVE* tests).
func RegisterUnlinkPath(path string) {
	if path == "" || IsAbstract(path) {
		return
	}
	unlinkMu.Lock()
	unlinkPaths = append(unlinkPaths, path)
	unlinkMu.Unlock()
}

// RegisterExitHook runs f on process signal exit (same path as UnlinkRegisteredPaths).
// Used for POSIX MQ unlink-close; mq names are not filesystem paths.
func RegisterExitHook(f func()) {
	if f == nil {
		return
	}
	unlinkMu.Lock()
	exitHooks = append(exitHooks, f)
	unlinkMu.Unlock()
}

// UnlinkRegisteredPaths removes all paths registered with RegisterUnlinkPath.
// Safe to call multiple times; best-effort (ignore errors).
func UnlinkRegisteredPaths() {
	unlinkMu.Lock()
	paths := slices.Clone(unlinkPaths)
	hooks := slices.Clone(exitHooks)
	unlinkMu.Unlock()
	for _, p := range paths {
		_ = os.Remove(p)
	}
	for _, h := range hooks {
		h()
	}
}
