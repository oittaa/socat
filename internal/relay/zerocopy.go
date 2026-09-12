// Zero-copy transfer plumbing shared by the platform implementations:
// policy gating, wrapper unwrapping down to kernel-copyable endpoints, and
// the plan interface that prepareZeroCopy returns.
package relay

import (
	"context"
	"errors"
	"io"
	"syscall"
)

// zeroCopyPlan is prepared before the cancellation goroutine can close either
// stream. Implementations own any duplicated descriptors and report read and
// write progress so idle timeouts and live statistics retain their normal
// semantics while data remains in the kernel.
type zeroCopyPlan interface {
	Copy(ctx context.Context, onRead, onWrite func(int64)) error
	Close() error
}

var errZeroCopyUnsupported = errors.New("zero-copy transfer unsupported")

// zeroCopyAllowed reports whether the transfer configuration permits
// zero-copy for one direction. This is policy only: runtime capability is
// discovered when a plan reports errZeroCopyUnsupported and the relay falls
// back to the configured-buffer path.
func zeroCopyAllowed(cfg Config, dir direction, usePoll bool) bool {
	if cfg.Verbose || cfg.Hex || usePoll {
		return false
	}
	if dir == dirLeftToRight && cfg.RawLeft != nil {
		return false
	}
	if dir == dirRightToLeft && cfg.RawRight != nil {
		return false
	}
	return true
}

func unwrapZeroCopyReader(s io.Reader) (syscall.Conn, bool) {
	if st, ok := s.(Stream); ok {
		conn := PropsOf(st).ZeroCopyRead
		return conn, conn != nil
	}
	return nil, false
}

func unwrapZeroCopyWriter(s io.Writer) (syscall.Conn, bool) {
	if st, ok := s.(Stream); ok {
		conn := PropsOf(st).ZeroCopyWrite
		return conn, conn != nil
	}
	return nil, false
}
