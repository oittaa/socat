//go:build linux || darwin

package xio

import (
	"sync"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

// umaskMu protects every address creation and child Start, including calls
// that do not request umask=. umask is process-wide, so locking only callers
// that change it still leaks the temporary value into concurrent operations.
var umaskMu sync.Mutex

func withConfiguredUmask(mask addrconfig.OptionalUint32, fn func() error) error {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	if !mask.Set {
		return fn()
	}
	old := unix.Umask(int(mask.Value))
	defer unix.Umask(old)
	return fn()
}
