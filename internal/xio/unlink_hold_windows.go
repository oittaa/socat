//go:build windows

package xio

import (
	"os"

	"golang.org/x/sys/windows"
)

// pinUnlinkPath keeps the NTFS file-id allocated so a replacement cannot reuse
// it. FILE_SHARE_DELETE lets the original name be unlinked while we hold it.
func pinUnlinkPath(path string) *os.File {
	u16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(u16, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0) // #nosec G304 -- endpoint path we created and are about to unregister on signal
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(h), path)
}
