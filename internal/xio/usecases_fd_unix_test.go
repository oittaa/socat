//go:build linux || darwin

package xio_test

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func duplicateFDNumber(t *testing.T, f *os.File) int {
	t.Helper()
	nfd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return nfd
}
