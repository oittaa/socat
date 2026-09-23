package xio

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"

	"github.com/oittaa/socat/internal/addrconfig"
)

// resolvePreparedOwners looks up user and group names before any address is
// opened. Numeric ids, including a leading-digit strtoul value, are kept.
func resolvePreparedOwners(config *addrconfig.Address) error {
	for i := range config.File.Actions {
		action := &config.File.Actions[i]
		var user bool
		switch action.Kind {
		case addrconfig.FileActionUser, addrconfig.FileActionUserEarly, addrconfig.FileActionUserLate:
			user = true
		case addrconfig.FileActionGroup, addrconfig.FileActionGroupEarly, addrconfig.FileActionGroupLate:
			user = false
		default:
			continue
		}
		resolved, err := resolveOwnerName(action.Owner, user)
		if err != nil {
			return err
		}
		action.Owner = resolved
	}
	return nil
}

func resolveOwnerName(owner addrconfig.OwnerRef, isUser bool) (addrconfig.OwnerRef, error) {
	if owner.Numeric || owner.Name == "" {
		return owner, nil
	}
	if isUser {
		account, err := user.Lookup(owner.Name)
		if err != nil {
			return addrconfig.OwnerRef{}, fmt.Errorf("user %q: no such user", owner.Name)
		}
		n, err := strconv.Atoi(account.Uid)
		if err != nil {
			return addrconfig.OwnerRef{}, fmt.Errorf("user %q: no such user", owner.Name)
		}
		owner.ID = n
		owner.Numeric = true
		return owner, nil
	}
	account, err := user.LookupGroup(owner.Name)
	if err != nil {
		return addrconfig.OwnerRef{}, fmt.Errorf("group %q: no such group", owner.Name)
	}
	n, err := strconv.Atoi(account.Gid)
	if err != nil {
		return addrconfig.OwnerRef{}, fmt.Errorf("group %q: no such group", owner.Name)
	}
	owner.ID = n
	owner.Numeric = true
	return owner, nil
}

// resolveUID uses a prepared user= / user-early= / user-late= reference.
// Numeric IDs are used as-is; only names hit the account database.
func resolveUID(owner addrconfig.OwnerRef) (int, bool, error) {
	if owner.Numeric {
		return owner.ID, true, nil
	}
	if owner.Name == "" {
		return -1, false, nil
	}
	u, err := user.Lookup(owner.Name)
	if err != nil {
		return -1, false, fmt.Errorf("user %q: %w", owner.Name, err)
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, false, err
	}
	return n, true, nil
}

// resolveGID uses a prepared group= / group-early= / group-late= reference.
// Numeric IDs are used as-is; only names hit the account database.
func resolveGID(owner addrconfig.OwnerRef) (int, bool, error) {
	if owner.Numeric {
		return owner.ID, true, nil
	}
	if owner.Name == "" {
		return -1, false, nil
	}
	g, err := user.LookupGroup(owner.Name)
	if err != nil {
		return -1, false, fmt.Errorf("group %q: %w", owner.Name, err)
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, false, err
	}
	return n, true, nil
}

// --- path unlink registry: named FS entries are removed on process exit ---

var (
	unlinkMu     sync.Mutex
	unlinkNextID uint64
	unlinkPaths  = make(map[uint64]unlinkEntry)
	exitHooks    []exitHook
)

type exitHook struct {
	id uint64
	fn func()
}

type unlinkEntry struct {
	path string
	info os.FileInfo
}

// RegisterUnlinkPath records a filesystem path to remove on process signal exit
// (SIGTERM etc.). The signal path uses os.Exit and would otherwise leave
// UNIX/PIPE/PTY entries.
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
	return RegisterUnlinkPathIdentity(path, info)
}

// RegisterUnlinkPathIdentity records path using a FileInfo already obtained
// from the owned object (typically f.Stat() of a still-open created fd).
// It does not Lstat the pathname again, so a replacement between create and
// register cannot be mistaken for the acquired object.
func RegisterUnlinkPathIdentity(path string, info os.FileInfo) func() {
	if path == "" || IsAbstract(path) || info == nil {
		return func() {}
	}
	if !SnapshotFileIdentity(info) {
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
// Hooks run in reverse registration order. POSIX MQ names are not filesystem
// paths, so they use this instead of RegisterUnlinkPath.
func RegisterExitHook(f func()) func() {
	if f == nil {
		return func() {}
	}
	unlinkMu.Lock()
	unlinkNextID++
	id := unlinkNextID
	exitHooks = append(exitHooks, exitHook{id: id, fn: f})
	unlinkMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			unlinkMu.Lock()
			exitHooks = removeExitHook(exitHooks, id)
			unlinkMu.Unlock()
		})
	}
}

func removeExitHook(hooks []exitHook, id uint64) []exitHook {
	for i, hook := range hooks {
		if hook.id == id {
			return append(hooks[:i], hooks[i+1:]...)
		}
	}
	return hooks
}

// UnlinkRegisteredPaths removes all paths registered with RegisterUnlinkPath
// and runs exit hooks in reverse registration order.
// Safe to call multiple times; best-effort (ignore errors).
func UnlinkRegisteredPaths() {
	unlinkMu.Lock()
	paths := make([]unlinkEntry, 0, len(unlinkPaths))
	for _, entry := range unlinkPaths {
		paths = append(paths, entry)
	}
	hooks := append([]exitHook(nil), exitHooks...)
	unlinkPaths = make(map[uint64]unlinkEntry)
	exitHooks = nil
	unlinkMu.Unlock()
	for _, entry := range paths {
		UnlinkIfSameFile(entry.path, entry.info)
	}
	for i := len(hooks) - 1; i >= 0; i-- {
		hooks[i].fn()
	}
}

// SnapshotFileIdentity records enough identity in info for a later
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
func SnapshotFileIdentity(info os.FileInfo) bool {
	return info != nil && os.SameFile(info, info)
}

// sameRegisteredFile reports whether current is still the object that was
// registered. unlink(2) removes a directory entry, not an inode; if the name
// now refers to a different file (st_dev/st_ino, or Windows volume+file index
// via os.SameFile), leave it. Mode/size/mtime are not part of that identity:
// they change on the live object (open, chmod, write) and must not skip unlink.
func sameRegisteredFile(original, current os.FileInfo) bool {
	return original != nil && current != nil && os.SameFile(original, current)
}

// unlinkIfSameFile removes path only when it still names original.
func UnlinkIfSameFile(path string, original os.FileInfo) {
	if path == "" || original == nil {
		return
	}
	current, err := os.Lstat(path)
	if err != nil || !sameRegisteredFile(original, current) {
		return
	}
	_ = Unlink(path)
}

// RegisteredUnlinkCount is the number of paths waiting for signal-exit cleanup.
func RegisteredUnlinkCount() int {
	unlinkMu.Lock()
	defer unlinkMu.Unlock()
	return len(unlinkPaths)
}
