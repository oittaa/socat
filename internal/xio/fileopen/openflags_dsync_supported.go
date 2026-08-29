//go:build darwin

package fileopen

import "golang.org/x/sys/unix"

const (
	oDSyncFlag      = unix.O_DSYNC
	oDSyncSupported = true
)
