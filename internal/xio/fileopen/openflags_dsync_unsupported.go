//go:build unix && !linux && !darwin && !netbsd && !openbsd && !aix && !solaris

package fileopen

const (
	oDSyncFlag      = 0
	oDSyncSupported = false
)
