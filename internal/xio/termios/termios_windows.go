//go:build windows

package termios

import (
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

// FeatureTERMIOS is off on Windows (no termios).
var FeatureTERMIOS = false

func TermiosHelpNames() []string { return nil }

func ApplyConfiguredTermios(_ int, _ addrconfig.Terminal) error { return nil }

func WaitPTYSlave(int, time.Duration) error { return nil }
