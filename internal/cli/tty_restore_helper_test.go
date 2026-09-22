package cli

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("SOCAT_TTY_RESTORE_HELPER") == "1" {
		os.Exit(Run([]string{
			os.Getenv("SOCAT_TTY_RESTORE_LEFT"),
			os.Getenv("SOCAT_TTY_RESTORE_RIGHT"),
		}, os.Exit))
	}
	os.Exit(m.Run())
}
