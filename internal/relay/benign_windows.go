//go:build windows

package relay

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isBenignPlatformClose reports Windows-specific broken pipe errors that
// correspond to Unix EPIPE when a peer pipe closes cleanly.
func isBenignPlatformClose(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA)
}
