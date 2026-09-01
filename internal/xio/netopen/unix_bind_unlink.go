package netopen

import (
	"fmt"
	"io"
	"os"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// unixBoundUnlink owns a bound filesystem UNIX path for close and SIGTERM.
// Close unlinks named unix sockets unless unlink-close=0 (bare flag → 1).
// Abstract names have no directory entry.
type unixBoundUnlink struct {
	doUnlink bool
	unreg    func()
	created  unixBindCreated
}

func trackUnixBind(path string, s parse.Spec) unixBoundUnlink {
	u := unixBoundUnlink{unreg: func() {}}
	if path == "" || xio.IsAbstract(path) {
		return u
	}
	u.created = rememberUnixBindCreated(path)
	u.doUnlink = !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if u.doUnlink && u.created.info != nil {
		u.unreg = xio.RegisterUnlinkPathIdentity(path, u.created.info)
	}
	return u
}

// prepareUnixFilesystemPath: unlink-early removes the name (ENOENT is
// informational); otherwise an existing filesystem entry is an error.
// reuseaddr does not unlink.
func prepareUnixFilesystemPath(path string, s parse.Spec) error {
	if path == "" || xio.IsAbstract(path) {
		return nil
	}
	if s.BoolOption("unlink-early") {
		// unlink(2), not os.Remove: Unlink refuses directories
		// (EISDIR). os.Remove would rmdir an empty directory.
		if err := xio.Unlink(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("unlink %s: %w", path, err)
		}
		return nil
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%q exists", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// drop unregisters, closes c, and removes the path when unlink-close is on.
// Use after bind when later setup fails.
func (u unixBoundUnlink) drop(c io.Closer) {
	u.unreg()
	logx.CloseQuiet(c)
	if u.doUnlink {
		u.created.unlink()
	}
}

// attach removes the path on Opened.Close / SIGTERM. Opened.Close already
// closes the stream or listener.
func (u unixBoundUnlink) attach(o *xio.Opened) {
	if !u.doUnlink {
		return
	}
	o.AddCleanup(func() {
		u.unreg()
		u.created.unlink()
	})
}
