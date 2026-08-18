//go:build e2e && unix

package e2e_test

import (
	"os"
	"syscall"
)

func signalUSR1(p *os.Process) error {
	return p.Signal(syscall.SIGUSR1)
}
