//go:build unix

package netopen

import "golang.org/x/sys/unix"

// unlinkPath is unlink(2): it removes a file or socket name and refuses
// directories (EISDIR). Classic xio_unlink calls Unlink() (sycls.c), which is
// unlink(2) (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official
// master af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
func unlinkPath(path string) error {
	return unix.Unlink(path)
}
