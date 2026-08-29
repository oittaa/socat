//go:build linux || darwin

package fileopen

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func duplicateFDForOpen(t *testing.T, f *os.File) (string, func() error) {
	t.Helper()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	return strconv.Itoa(fd), func() error { return unix.Close(fd) }
}
