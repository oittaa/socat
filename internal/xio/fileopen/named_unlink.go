package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// namedEarly is classic _xioopen_named_early (xio-named.c, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
//
// os.Stat follows symlinks, matching classic Stat(). unlink-early (PH_EARLY)
// may set exists false. If the name still exists, applyopts_named PH_PREOPEN
// walks s.Options in command-line order (perm-early, user-early, group-early,
// unlink). Those ops do not change exists or the recorded type, so GOPEN
// keeps the original existing-file / socket classification. A missing name
// drops PH_PREOPEN (classic dropopts): no chmod/chown/unlink of a hole.
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
	// unlink(2), not os.Remove: classic Unlink() refuses directories.
	if err := xio.Unlink(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unlink %s: %w", path, err)
	}
	return nil
}

// applyNamedUnlinkLate is classic PH_PASTOPEN unlink-late. ENOENT is a warning
// in xio-named.c; any other Unlink() error is Error() and aborts (exitlevel
// E_ERROR).
func applyNamedUnlinkLate(path string, s parse.Spec) error {
	// Same classic applyopts_named presence bug as unlink=0; honor the bool.
	if !s.BoolOption("unlink-late") {
		return nil
	}
	return unlinkNamed(path)
}

// namedUnlinkGuard is classic unlink-close (PH_LATE): armed after a successful
// open/connect so later setup failures still remove the name, then transferred
// to Opened.Cleanup once construction succeeds. OPEN/CREATE/GOPEN default it
// off. unlink-late (PH_PASTOPEN) is applied immediately after open, before
// this guard is installed.
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
