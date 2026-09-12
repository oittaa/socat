//go:build windows

package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
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

func mirrorInheritedFDFlags(orig int, _ *os.File, config addrconfig.File) error {
	for _, action := range config.Actions {
		if action.Kind != addrconfig.FileActionNoInherit {
			continue
		}
		flags := uint32(0)
		if !action.Enabled {
			flags = windows.HANDLE_FLAG_INHERIT
		}
		if err := windows.SetHandleInformation(windows.Handle(orig), windows.HANDLE_FLAG_INHERIT, flags); err != nil {
			return fmt.Errorf("%s: SetHandleInformation: %w", action.Name, err)
		}
	}
	return nil
}
