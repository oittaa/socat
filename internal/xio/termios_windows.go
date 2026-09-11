//go:build windows

package xio

import (
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// FeatureTERMIOS is off on Windows (no termios).
var FeatureTERMIOS = false

func TermiosHelpNames() []string { return nil }

func ValidateTermiosOption(parse.Option) error { return nil }

func ApplyConfiguredTermios(_ int, _ addrconfig.Terminal) error { return nil }

func AttachConfiguredTermios(_ *Opened, _ int, _ addrconfig.Terminal) error { return nil }

func WaitPTYSlave(int, time.Duration) error { return nil }
