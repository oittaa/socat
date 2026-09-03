//go:build privileged && (linux || darwin)

package privileged_test

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "privileged tests require root; run with sudo")
		os.Exit(1)
	}
	os.Exit(m.Run())
}
