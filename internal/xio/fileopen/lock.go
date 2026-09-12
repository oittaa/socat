package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
)

func applyConfiguredFileLocks(config addrconfig.File, readFile, writeFile *os.File) error {
	for _, action := range config.Actions {
		var file *os.File
		var write, wait bool
		switch action.Kind {
		case addrconfig.FileActionLock:
			switch action.Value {
			case 1:
				file, write = writeFile, true
			case 2:
				file, write, wait = writeFile, true, true
			case 3:
				file = readFile
			case 4:
				file, wait = readFile, true
			}
		default:
			continue
		}
		if !action.Enabled {
			continue
		}
		if file == nil {
			return fmt.Errorf("%s: address has no applicable file descriptor", action.Name)
		}
		if err := lockFile(file, write, wait); err != nil {
			return fmt.Errorf("%s: %w", action.Name, err)
		}
	}
	return nil
}
