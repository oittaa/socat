//go:build linux || darwin

package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/testutil"
)

func unixSocketTestPath(t *testing.T, name string) string {
	t.Helper()
	return testutil.UnixSocketPath(t, name)
}
