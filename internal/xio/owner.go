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
	// hold pins the registered inode so a replacement cannot recycle its
	// identity (Linux O_PATH, Darwin O_EVTONLY, Windows FILE_SHARE_DELETE).
	// Must not be a FIFO reader. Closed before os.Remove so Darwin can unlink
	// a FIFO that still has a blocked open.
	hold *os.File
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
	hold := pinUnlinkPath(path)
	unlinkMu.Lock()
	unlinkNextID++
	id := unlinkNextID
	unlinkPaths[id] = unlinkEntry{path: path, info: info, hold: hold}
	unlinkMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			unlinkMu.Lock()
			delete(unlinkPaths, id)
			unlinkMu.Unlock()
			if hold != nil {
				_ = hold.Close()
			}
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
		same := err == nil && sameRegisteredFile(entry.info, current)
		// Drop the pin before unlink: Darwin can refuse to remove a FIFO while
		// an O_EVTONLY descriptor still names that vnode.
		if entry.hold != nil {
			_ = entry.hold.Close()
		}
		if same {
			_ = os.Remove(entry.path)
		}
	}
	for _, h := range hooks {
		h()
	}
}

// sameRegisteredFile reports whether current is the object that was registered.
// Classic unlinks the stored path with no identity check. We skip replacements
// at the same name (dev+inode via SameFile). Mode/size/mtime are not compared:
// they change on the live object (open, chmod, write) and would skip PIPE_REMOVE
// cleanup. Inode reuse is handled by pinUnlinkPath, not by metadata.
func sameRegisteredFile(original, current os.FileInfo) bool {
	return original != nil && current != nil && os.SameFile(original, current)
}

// RegisteredUnlinkCount is the number of paths waiting for signal-exit cleanup.
func RegisteredUnlinkCount() int {
	unlinkMu.Lock()
	defer unlinkMu.Unlock()
	return len(unlinkPaths)
}
