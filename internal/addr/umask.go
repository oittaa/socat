package addr

import (
	"strconv"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// withUmask temporarily sets the process umask for named file/socket creation
// (classic option umask=octal). Restores the previous mask afterward.
func withUmask(s parse.Spec, fn func() error) error {
	if !s.HasOption("umask") {
		return fn()
	}
	v := s.OptionValue("umask", "")
	if v == "" {
		return fn()
	}
	// Classic TYPE_MODET is octal (umask=177 → 0o177).
	mask, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		mask, err = strconv.ParseUint(v, 0, 32)
		if err != nil {
			return fn() // ignore bad value rather than fail open
		}
	}
	old := unix.Umask(int(mask))
	defer unix.Umask(old)
	return fn()
}
