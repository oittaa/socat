package fileopen

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// inheritedSessionLive is the number of open per-session duplicates of an
// inherited FD. Tests use it to prove repeated opens do not leak wrappers.
var inheritedSessionLive atomic.Int64

// inheritedSession closes the per-session duplicate. With end-close it also
// closes the original inherited descriptor.
type inheritedSession struct {
	session   *os.File
	orig      int
	closeOrig bool
	once      sync.Once
	err       error
}

func (s *inheritedSession) Close() error {
	s.once.Do(func() {
		s.err = s.session.Close()
		inheritedSessionLive.Add(-1)
		if s.closeOrig {
			if e := closeInheritedFD(s.orig); e != nil && s.err == nil {
				s.err = e
			}
		}
	})
	return s.err
}

func closeSessionFile(f *os.File) {
	_ = f.Close()
	inheritedSessionLive.Add(-1)
}

func inheritedFDStream(f *os.File, orig int, closeOrig bool) relay.Stream {
	return relay.FDStream{
		R: f,
		W: f,
		C: &inheritedSession{session: f, orig: orig, closeOrig: closeOrig},
	}
}

// specWithoutEndClose copies s without end-close. WrapCommon treats that
// option as "keep the peer FD open" (EXEC reuse). FD uses the opposite
// meaning: close the inherited descriptor on EOF.
func specWithoutEndClose(s parse.Spec) parse.Spec {
	opts := make([]parse.Option, 0, len(s.Options))
	changed := false
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) == "end-close" {
			changed = true
			continue
		}
		opts = append(opts, o)
	}
	if !changed {
		return s
	}
	s.Options = opts
	return s
}
