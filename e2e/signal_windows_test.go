//go:build e2e && windows

package e2e_test

import (
	"fmt"
	"os"
)

func signalUSR1(*os.Process) error {
	return fmt.Errorf("no SIGUSR1 on Windows")
}
