//go:build windows

package xio

import (
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// FeatureTERMIOS is off on Windows (no termios).
var FeatureTERMIOS = false

func TermiosHelpNames() []string { return nil }

func ValidateTermiosOption(parse.Option) error { return nil }

func ApplyTermios(_ int, s parse.Spec) error {
	return RejectUnsupportedTermios(s)
}

func AttachTermios(_ *Opened, _ int, s parse.Spec) error {
	return RejectUnsupportedTermios(s)
}

func WaitPTYSlave(int, time.Duration) error { return nil }

func PTYWaitInterval(parse.Spec) time.Duration { return time.Second }
