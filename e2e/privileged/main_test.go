//go:build e2e && privileged && darwin

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
	if os.Getenv("SOCAT") == "" {
		fmt.Fprintln(os.Stderr, "set SOCAT to the absolute path of the built socat binary")
		os.Exit(1)
	}
	os.Exit(m.Run())
}
