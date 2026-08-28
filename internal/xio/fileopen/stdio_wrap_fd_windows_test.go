//go:build windows

package fileopen

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
)

func duplicateFDForOpen(t *testing.T, f *os.File) (string, func() error) {
	t.Helper()
	process := windows.CurrentProcess()
	var handle windows.Handle
	if err := windows.DuplicateHandle(
		process,
		windows.Handle(f.Fd()),
		process,
		&handle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		t.Fatal(err)
	}
	return strconv.FormatUint(uint64(handle), 10), func() error { return windows.CloseHandle(handle) }
}
