//go:build windows

package xio

import (
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// FeatureTERMIOS is off on Windows (no termios).
var FeatureTERMIOS = false

func TermiosHelpNames() []string { return nil }

func ApplyTermios(int, parse.Spec) error { return nil }

func AttachTermios(*Opened, int, parse.Spec) error { return nil }

func WaitPTYSlave(int, time.Duration) error { return nil }

func PTYWaitInterval(parse.Spec) time.Duration { return time.Second }
