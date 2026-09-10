//go:build e2e && darwin && !cgo

package e2e

import "fmt"

// ProcessListens is unavailable without cgo; Darwin FD inspection uses libproc.
func ProcessListens(int, string, string) (bool, error) {
	return false, fmt.Errorf("darwin listen-owner check requires cgo")
}
