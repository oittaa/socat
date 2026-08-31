package xio

import (
	"fmt"
	"os"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyNamedPreopen applies perm-early / user-early / group-early and unlink
// to an existing filesystem path, in command-line order, before open.
// unlink=0 does not delete.
//
// Callers must invoke this only when the name exists. UNIX bind paths call
// ApplyNamedAfterBind once the directory entry exists.
func ApplyNamedPreopen(path string, s parse.Spec) error {
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "perm-early":
			mode, err := parseModeT("perm-early", o.Value)
			if err != nil {
				return err
			}
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
		case "user-early":
			uid, has, err := resolveUID(o.Value)
			if err != nil {
				return err
			}
			if !has {
				continue
			}
			if err := os.Chown(path, uid, -1); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		case "group-early":
			gid, has, err := resolveGID(o.Value)
			if err != nil {
				return err
			}
			if !has {
				continue
			}
			if err := os.Chown(path, -1, gid); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		case "unlink":
			// unlink=0 does not delete.
			if !o.Active() {
				continue
			}
			if err := Unlink(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("unlink %s: %w", path, err)
			}
		}
	}
	return nil
}

// ApplyNamedAfterBind applies named options to a filesystem UNIX socket
// after bind. UNIX-CONNECT and UNIX-SENDTO apply those options to the
// socket descriptor instead. Abstract names have no filesystem entry.
//
// perm-early is a no-op before bind because the directory entry does not
// exist yet; after bind it chmods the new socket and wins over perm= on
// listen/recv names. unlink= at this phase would remove the just-bound name.
func ApplyNamedAfterBind(path string, s parse.Spec, f *os.File) error {
	if path == "" || IsAbstract(path) {
		return nil
	}
	// Named path attrs after bind only for filesystem UNIX-LISTEN /
	// UNIX-RECV / UNIX-RECVFROM. UNIX-CONNECT and UNIX-SENDTO apply them
	// to the socket descriptor instead.
	if namedFilesystemUnixPHFD(s) {
		if err := ApplyNamedAttrs(path, s, f); err != nil {
			return err
		}
	}
	return ApplyNamedPreopen(path, s)
}

func parseModeT(name, v string) (os.FileMode, error) {
	m, err := strconv.ParseUint(v, 8, 32)
	if err != nil || m > 0o7777 {
		return 0, fmt.Errorf("invalid %s %q", name, v)
	}
	return UnixModeToFileMode(uint32(m)), nil
}
