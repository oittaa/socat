//go:build linux || darwin

package xio

import "golang.org/x/sys/unix"

// Unlink is unlink(2): it removes a file, FIFO, or socket name and refuses
// directories (Linux EISDIR, Darwin EPERM).
func Unlink(path string) error {
	return unix.Unlink(path)
}
