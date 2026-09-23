//go:build linux

package execopen

import (
	"testing"

	"github.com/oittaa/socat/internal/xio/termios"
)

func TestOpenPTYPairMultipleLivePairs(t *testing.T) {
	var firstSlave string
	for range 2 {
		master, slave, err := termios.OpenPTYPair()
		if err != nil {
			t.Fatal(err)
		}
		// Keep both pairs open so at least one has a nonzero PTY number.
		t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
		if slave.Name() == firstSlave {
			t.Fatalf("two live PTY pairs share slave %s", firstSlave)
		}
		firstSlave = slave.Name()
	}
}
