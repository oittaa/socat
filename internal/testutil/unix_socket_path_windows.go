//go:build windows

package testutil

import "os"

func unixSocketTempRoot() string { return os.TempDir() }
