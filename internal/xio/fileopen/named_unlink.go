package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// namedEarly is the pre-open os.Stat snapshot. os.Stat follows symlinks.
// unlink-early may set exists false. If the name still exists, perm-early /
// user-early / group-early / unlink run in command-line order without
// changing exists or type. A missing name skips those ops.
type namedEarly struct {
	exists bool
	mode   os.FileMode
}

func namedOpenEarly(path string, s parse.Spec) (namedEarly, error) {
	var n namedEarly
	fi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return n, fmt.Errorf("stat %s: %w", path, err)
		}
	} else {
		n.exists = true
		n.mode = fi.Mode()
	}

	if n.exists && s.BoolOption("unlink-early") {
		if err := unlinkNamed(path); err != nil {
			return n, err
		}
		n.exists = false
	}

	if n.exists {
		if err := xio.ApplyNamedPreopen(path, s); err != nil {
			return n, err
		}
	}
	return n, nil
}

func unlinkNamed(path string) error {
	// unlink(2), not os.Remove: Unlink refuses directories.
	if err := xio.Unlink(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unlink %s: %w", path, err)
	}
	return nil
}

// applyNamedUnlinkLate is unlink-late immediately after open. ENOENT is
// ignored; any other Unlink error aborts.
func applyNamedUnlinkLate(path string, s parse.Spec) error {
	// unlink-late=0 does not delete (documented boolean; presence is not enough).
	if !s.BoolOption("unlink-late") {
		return nil
	}
	return unlinkNamed(path)
}

// namedUnlinkGuard is unlink-close: armed after a successful open/connect
// so later setup failures still remove the name, then transferred to
// Opened.Cleanup. OPEN/CREATE/GOPEN default it off. unlink-late runs
// immediately after open, before this guard is installed.
type namedUnlinkGuard struct {
	path    string
	closeOn bool
	unreg   func()
}

func namedAfterOpen(path string, s parse.Spec) (namedUnlinkGuard, error) {
	if err := applyNamedUnlinkLate(path, s); err != nil {
		return namedUnlinkGuard{unreg: func() {}}, err
	}
	g := namedUnlinkGuard{path: path, unreg: func() {}}
	if s.BoolOption("unlink-close") {
		g.closeOn = true
		g.unreg = xio.RegisterUnlinkPath(path)
	}
	return g, nil
}

func (g namedUnlinkGuard) drop() {
	g.unreg()
	if g.closeOn {
		_ = xio.Unlink(g.path)
	}
}

func (g namedUnlinkGuard) attach(o *xio.Opened) {
	if !g.closeOn {
		return
	}
	unreg := g.unreg
	path := g.path
	o.AddCleanup(func() {
		unreg()
		_ = xio.Unlink(path)
	})
}
