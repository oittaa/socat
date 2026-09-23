//go:build linux || darwin

package xio

import (
	"fmt"
	"sync"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio/termios"
	"golang.org/x/sys/unix"
)

// AttachConfiguredTermios saves, applies, and restores typed terminal state.
func AttachConfiguredTermios(o *Opened, fd int, config addrconfig.Terminal) error {
	var saved *unix.Termios
	if termios.HasConfiguredTermiosState(config) {
		var err error
		saved, err = termios.GetTermios(fd)
		if err != nil {
			return fmt.Errorf("termios: %w", err)
		}
	}
	if err := termios.ApplyConfiguredTermios(fd, config); err != nil {
		return err
	}
	if saved == nil {
		return nil
	}
	// Signal exit calls os.Exit and skips Close. Register the same restore
	// there, and drop it once Close has restored this fd. The relay also
	// closes the stream before Opened.Close, so that close restores first.
	cp := *saved
	var mu sync.Mutex
	live := true
	restore := func() {
		mu.Lock()
		defer mu.Unlock()
		if !live {
			return
		}
		live = false
		_ = termios.SetTermios(fd, &cp)
	}
	unregister := RegisterExitHook(restore)
	o.AddTTYRestore(func() {
		unregister()
		restore()
	})
	o.wrapStreamTTYRestore(restore)
	return nil
}

// ttyRestoreStream runs restore before the inner stream closes its descriptor.
type ttyRestoreStream struct {
	relay.Stream
	restore func()
}

func (s *ttyRestoreStream) Close() error {
	if s.restore != nil {
		s.restore()
	}
	return s.Stream.Close()
}

// ShutdownWrite restores when the half-close closes the descriptor.
// shut-close does. Default, shut-none, shut-down, and end-close do not.
func (s *ttyRestoreStream) ShutdownWrite() error {
	if s.restore != nil && streamClosesOnHalfClose(s.Stream) {
		s.restore()
	}
	return s.Stream.ShutdownWrite()
}

// streamClosesOnHalfClose asks the stream that owns ShutdownWrite.
// An opaque descriptor, including a nested FDStream, does not close.
func streamClosesOnHalfClose(s relay.Stream) bool {
	cur := s
	for range 16 {
		if cur == nil {
			return false
		}
		if c, ok := cur.(interface{ closesOnHalfClose() bool }); ok {
			return c.closesOnHalfClose()
		}
		u, ok := cur.(interface{ UnwrapStream() relay.Stream })
		if !ok {
			return false
		}
		next := u.UnwrapStream()
		if next == nil {
			return false
		}
		cur = next
	}
	return false
}

func (s *ttyRestoreStream) UnwrapStream() relay.Stream { return s.Stream }

// IsEndClose keeps end-close visible. Attach runs after WrapAfterFD, so this
// wrapper is outside endCloseStream.
func (s *ttyRestoreStream) IsEndClose() bool {
	return streamIsEndClose(s.Stream)
}

func (o *Opened) wrapStreamTTYRestore(restore func()) {
	p := o.ready()
	if p == nil || p.stream == nil || restore == nil {
		return
	}
	p.stream = &ttyRestoreStream{Stream: p.stream, restore: restore}
}
