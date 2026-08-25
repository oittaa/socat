package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// namedUnlinkBeforeOpen implements classic PH_EARLY unlink-early and
// PH_PREOPEN unlink/delete/remove (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
// Missing names are ignored (xio_unlink ENOENT is informational).
func namedUnlinkBeforeOpen(path string, s parse.Spec) error {
	if !s.BoolOption("unlink-early") && !s.BoolOption("unlink") {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unlink %s: %w", path, err)
	}
	return nil
}

// applyNamedUnlinkAfterOpen implements PH_PASTOPEN unlink-late (immediately,
// fd kept) and PH_LATE unlink-close (on Close / SIGTERM). Classic OPEN/CREATE
// /GOPEN default unlink-close off.
func applyNamedUnlinkAfterOpen(o *xio.Opened, s parse.Spec, path string) {
	if s.BoolOption("unlink-late") {
		_ = os.Remove(path)
	}
	if !s.BoolOption("unlink-close") {
		return
	}
	unregister := xio.RegisterUnlinkPath(path)
	o.AddCleanup(func() {
		unregister()
		_ = os.Remove(path)
	})
}
