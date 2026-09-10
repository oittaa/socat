//go:build e2e && (darwin || windows)

package e2e_test

import (
	"fmt"
	"time"
)

func waitSCTPTestProcess(*testProcess, int, time.Duration) error {
	return fmt.Errorf("SCTP listen wait is not implemented on this platform")
}
