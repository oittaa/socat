//go:build e2e && linux

package e2e_test

import (
	"syscall"
	"testing"
)

func TestExitCodeOnSignalILL(t *testing.T) {
	runExitCodeOnSignal(t, syscall.SIGILL, "exiting on signal 4")
}
