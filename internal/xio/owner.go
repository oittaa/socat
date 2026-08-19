package xio

import (
	"fmt"
	"os"
	"os/user"
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
	unlinkMu     sync.Mutex
	unlinkNextID uint64
	unlinkPaths  = make(map[uint64]unlinkEntry)
	exitHooks    = make(map[uint64]func())
)

type unlinkEntry struct {
	path string
	info os.FileInfo
}

// RegisterUnlinkPath records a filesystem path to remove on process signal exit
// (SIGTERM etc.). Classic xio_close unlinks; our signal path uses os.Exit and
// would otherwise leave UNIX/PIPE/PTY link entries (REMOVE* tests).
func RegisterUnlinkPath(path string) func() {
	if path == "" || IsAbstract(path) {
		return func() {}
	}
	info, err := os.Lstat(path)
	if err != nil {
		// Never register a path whose current object identity is unknown: a
		// later file at that name might belong to somebody else.
		return func() {}
	}
	unlinkMu.Lock()
	unlinkNextID++
	id := unlinkNextID
	unlinkPaths[id] = unlinkEntry{path: path, info: info}
	unlinkMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			unlinkMu.Lock()
			delete(unlinkPaths, id)
			unlinkMu.Unlock()
		})
	}
}

// RegisterExitHook runs f on process signal exit (same path as UnlinkRegisteredPaths).
// Used for POSIX MQ unlink-close; mq names are not filesystem paths.
func RegisterExitHook(f func()) func() {
	if f == nil {
		return func() {}
	}
	unlinkMu.Lock()
	unlinkNextID++
	id := unlinkNextID
	exitHooks[id] = f
	unlinkMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			unlinkMu.Lock()
			delete(exitHooks, id)
			unlinkMu.Unlock()
		})
	}
}

// UnlinkRegisteredPaths removes all paths registered with RegisterUnlinkPath.
// Safe to call multiple times; best-effort (ignore errors).
func UnlinkRegisteredPaths() {
	unlinkMu.Lock()
	paths := make([]unlinkEntry, 0, len(unlinkPaths))
	for _, entry := range unlinkPaths {
		paths = append(paths, entry)
	}
	hooks := make([]func(), 0, len(exitHooks))
	for _, hook := range exitHooks {
		hooks = append(hooks, hook)
	}
	unlinkPaths = make(map[uint64]unlinkEntry)
	exitHooks = make(map[uint64]func())
	unlinkMu.Unlock()
	for _, entry := range paths {
		current, err := os.Lstat(entry.path)
		if err != nil || !sameRegisteredFile(entry.info, current) {
			continue
		}
		_ = os.Remove(entry.path)
	}
	for _, h := range hooks {
		h()
	}
}

func sameRegisteredFile(original, current os.FileInfo) bool {
	return original != nil && current != nil &&
		os.SameFile(original, current) &&
		original.Mode() == current.Mode() &&
		original.Size() == current.Size() &&
		original.ModTime().Equal(current.ModTime())
}
