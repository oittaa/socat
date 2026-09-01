//go:build windows

package xio_test

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func duplicateFDNumber(t *testing.T, f *os.File) int {
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
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return int(handle)
}
