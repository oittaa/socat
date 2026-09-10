//go:build e2e && darwin

package e2e_test

import "github.com/oittaa/socat/e2e"

func processListens(pid int, network, addr string) (bool, error) {
	return e2e.ProcessListens(pid, network, addr)
}
