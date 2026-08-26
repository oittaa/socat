//go:build unix

package xio

import "golang.org/x/sys/unix"

// Unlink is unlink(2): it removes a file, FIFO, or socket name and refuses
// directories (Linux EISDIR, Darwin/BSD EPERM). Classic xio_unlink calls
// Unlink() in sycls.c, which is unlink(2) (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
func Unlink(path string) error {
	return unix.Unlink(path)
}
