//go:build unix

package xio

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// umaskMu protects every address creation and child Start, including calls
// that do not request umask=. umask is process-wide, so locking only callers
// that change it still leaks the temporary value into concurrent operations.
var umaskMu sync.Mutex

// WithUmask temporarily sets the process umask for named file/socket creation
// (classic option umask=octal). Restores the previous mask afterward.
func WithUmask(s parse.Spec, fn func() error) error {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	o, requested := s.OptionNamed("umask")
	if !requested {
		return fn()
	}
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return fmt.Errorf("%s: option %q requires a value", s.Type, o.Name)
	}
	// Classic TYPE_MODET is octal (umask=177 → 0o177).
	mask, err := strconv.ParseUint(v, 8, 32)
	if err != nil || mask > 0o777 {
		return fmt.Errorf("%s: invalid umask %q", s.Type, v)
	}
	old := unix.Umask(int(mask))
	defer unix.Umask(old)
	return fn()
}
