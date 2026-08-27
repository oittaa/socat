package xio

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyOwner applies every classic user=/uid=/owner= and group=/gid=
// occurrence to a named object in command-line order. perm=/mode= is omitted
// because regular files and FIFOs already consumed it as their creation mode.
func ApplyOwner(path string, s parse.Spec, f *os.File) error {
	// CREATE/CREAT use creat(2), then classic applyopts2 applies user/group
	// to the descriptor at PH_FD. ApplyFDOptions owns that path; do not also
	// chown the pathname here. OPEN/FILE/GOPEN and named FIFOs use NAMED.
	switch strings.ToUpper(s.Type) {
	case "CREATE", "CREAT":
		return nil
	}
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "user":
			if err := applyNamedUser(path, f, o); err != nil {
				return err
			}
		case "group":
			if err := applyNamedGroup(path, f, o); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolveUID parses user=/user-early= as a numeric uid or login name.
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

// resolveGID parses group=/group-early= as a numeric gid or group name.
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
// (SIGTERM etc.). Classic xio_close calls unlink(2) on the stored name; our
// signal path uses os.Exit and would otherwise leave UNIX/PIPE/PTY entries
// (REMOVE* tests).
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
	if !snapshotRegisteredIdentity(info) {
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
		_ = Unlink(entry.path)
	}
	for _, h := range hooks {
		h()
	}
}

// snapshotRegisteredIdentity records enough identity in info for a later
// os.SameFile check, without keeping a descriptor open.
//
// Extra fds were the wrong tool: Linux unlink(2) removes the name while any
// already-open endpoint fd holds the inode; Darwin O_EVTONLY is a kqueue
// monitor flag (open(2)) and open() of a FIFO with it still waits for a
// writer; Windows DeleteFile fails while another handle is open without
// FILE_SHARE_DELETE.
//
// Unix Lstat already has st_dev/st_ino. Windows Lstat uses GetFileAttributesEx
// and leaves the file index unset; os.SameFile then re-opens the path (Go
// os/types_windows.go loadFileId) and would treat a replacement as the
// original. Calling SameFile now snapshots the index while this object still
// owns the name, then closes that brief handle.
func snapshotRegisteredIdentity(info os.FileInfo) bool {
	return info != nil && os.SameFile(info, info)
}

// sameRegisteredFile reports whether current is still the object that was
// registered. unlink(2) removes a directory entry, not an inode; if the name
// now refers to a different file (st_dev/st_ino, or Windows volume+file index
// via os.SameFile), leave it. Mode/size/mtime are not part of that identity:
// they change on the live object (open, chmod, write) and must not skip
// PIPE_REMOVE.
func sameRegisteredFile(original, current os.FileInfo) bool {
	return original != nil && current != nil && os.SameFile(original, current)
}

// RegisteredUnlinkCount is the number of paths waiting for signal-exit cleanup.
func RegisteredUnlinkCount() int {
	unlinkMu.Lock()
	defer unlinkMu.Unlock()
	return len(unlinkPaths)
}
