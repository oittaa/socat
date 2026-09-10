//go:build e2e && darwin && !cgo

package e2e_test

import "fmt"

func processListens(int, string, string) (bool, error) {
	return false, fmt.Errorf("darwin listen-owner check requires cgo")
}
