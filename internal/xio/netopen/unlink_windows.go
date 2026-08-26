//go:build windows

package netopen

import "golang.org/x/sys/windows"

// unlinkPath removes a file or socket name without removing directories.
// DeleteFile is the Windows analog of unlink(2); RemoveDirectory is not.
func unlinkPath(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.DeleteFile(p)
}
