package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
)

// applyFileLocks implements classic socat's whole-file fcntl lock options.
// Write locks belong to the address's output descriptor and read locks to its
// input descriptor. A regular FILE/OPEN descriptor is commonly both.
func applyFileLocks(s parse.Spec, readFile, writeFile *os.File) error {
	locks := []struct {
		option string
		file   *os.File
		write  bool
		wait   bool
	}{
		{"setlk", writeFile, true, false},
		{"setlkw", writeFile, true, true},
		{"setlk-rd", readFile, false, false},
		{"setlkw-rd", readFile, false, true},
	}
	for _, lock := range locks {
		if !s.HasOption(lock.option) || !s.BoolOption(lock.option) {
			continue
		}
		if lock.file == nil {
			return fmt.Errorf("%s: address has no applicable file descriptor", lock.option)
		}
		if err := lockFile(lock.file, lock.write, lock.wait); err != nil {
			return fmt.Errorf("%s: %w", lock.option, err)
		}
	}
	return nil
}
