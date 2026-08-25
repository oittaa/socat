//go:build !linux && !darwin

package xio

import "os"

// holdUnlinkIdentity records Lstat identity. Platforms without O_PATH/O_EVTONLY
// cannot pin the inode, so a same-inode replacement after unlink is possible.
func holdUnlinkIdentity(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	return nil, info, err
}
