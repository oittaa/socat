//go:build windows

package cli

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// A Windows name can remain briefly unavailable after Remove succeeds while
// the old file is delete-pending. Concurrent CREATE_NEW attempts report one of
// these errors until the final handle is released.
func isTransientLockCreateError(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
