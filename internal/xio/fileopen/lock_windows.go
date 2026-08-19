//go:build windows

package fileopen

import (
	"fmt"
	"os"
)

func lockFile(*os.File, bool, bool) error {
	return fmt.Errorf("fcntl file locks are not supported on Windows")
}
