package netopen

import (
	"io"
	"os"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// unixBoundUnlink owns a bound filesystem UNIX path for close and SIGTERM.
// Classic xio_close unlinks NAMED unix sockets unless unlink-close=0
// (tag-1.8.1.3 / af5388c). Abstract names have no directory entry.
type unixBoundUnlink struct {
	path     string
	doUnlink bool
	unreg    func()
}

func trackUnixBind(path string, s parse.Spec) unixBoundUnlink {
	u := unixBoundUnlink{unreg: func() {}}
	if path == "" || xio.IsAbstract(path) {
		return u
	}
	u.path = path
	u.doUnlink = !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if u.doUnlink {
		u.unreg = xio.RegisterUnlinkPath(path)
	}
	return u
}

// drop unregisters, closes c, and removes the path when unlink-close is on.
// Use after bind when later setup fails.
func (u unixBoundUnlink) drop(c io.Closer) {
	u.unreg()
	logx.CloseQuiet(c)
	if u.doUnlink {
		_ = os.Remove(u.path)
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
		_ = os.Remove(u.path)
	})
}
