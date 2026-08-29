//go:build windows

package xio

import (
	"os"

	"golang.org/x/sys/windows"
)

// Unlink removes a file, socket name, or symbolic link without removing real
// directories. DeleteFile is the Windows analog of unlink(2) for non-directory
// names. Directory symlinks and junctions require RemoveDirectory, which
// removes the link rather than its target.
//
// os.Remove also rmdirs empty directories and, on ACCESS_DENIED, retries after
// clearing FILE_ATTRIBUTE_READONLY. unlink(2) unlinks a mode-0400 file
// (directory write permission is enough) but refuses directories, so we keep
// the readonly retry and skip RemoveDirectory.
func Unlink(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.DeleteFile(p)
	if err == nil {
		return nil
	}
	attrs, aerr := windows.GetFileAttributes(p)
	if aerr != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		if _, lerr := os.Readlink(path); lerr != nil {
			return err
		}
		return windows.RemoveDirectory(p)
	}
	if attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return err
	}
	if serr := windows.SetFileAttributes(p, attrs&^windows.FILE_ATTRIBUTE_READONLY); serr != nil {
		return err
	}
	return windows.DeleteFile(p)
}
