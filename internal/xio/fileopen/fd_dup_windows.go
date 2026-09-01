//go:build windows

package fileopen

import (
	"os"

	"golang.org/x/sys/windows"
)

func duplicateInheritedFD(fd int) (int, error) {
	process := windows.CurrentProcess()
	var handle windows.Handle
	if err := windows.DuplicateHandle(
		process,
		windows.Handle(fd),
		process,
		&handle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return -1, err
	}
	return int(handle), nil
}

func closeInheritedFD(fd int) error {
	return windows.CloseHandle(windows.Handle(fd))
}

func mirrorInheritedCloexec(int, *os.File) error { return nil }
