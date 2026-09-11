//go:build darwin

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

// applyConfiguredLinuxPHFDAction rejects Linux-only after-open options that
// still decode so they fail at apply time instead of becoming a silent no-op.
func applyConfiguredLinuxPHFDAction(_ int, action addrconfig.FileAction) error {
	switch action.Kind {
	case addrconfig.FileActionNoAtime:
		if action.Enabled {
			return fmt.Errorf("o-noatime: not supported on this platform")
		}
	case addrconfig.FileActionPipeSize:
		return fmt.Errorf("f-setpipe-sz: not supported on this platform")
	case addrconfig.FileActionFSFlag:
		if action.Enabled {
			return fmt.Errorf("%s: not supported on this platform", action.Name)
		}
	}
	return nil
}
