//go:build windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyGenericIoctlOption recognizes generic ioctl options on Windows so
// they are not unknown, then rejects them. Parse still runs first so
// malformed values fail as invalid rather than "not supported".
func applyGenericIoctlOption(_ int, o parse.Option) error {
	if _, err := parseGenericIoctl(o); err != nil {
		return err
	}
	return fmt.Errorf("%s: not supported on windows", o.OriginalSpelling())
}
