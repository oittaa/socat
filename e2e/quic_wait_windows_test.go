//go:build e2e && windows

package e2e_test

import (
	"testing"
	"time"
)

func waitUDPListen(t *testing.T, _ int, _ time.Duration) {
	t.Helper()
	// Windows SO_REUSEADDR lets a second UDP bind succeed, so a
	// ListenPacket probe cannot see that the server already holds the port.
	time.Sleep(250 * time.Millisecond)
}
