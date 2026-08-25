//go:build !linux && !darwin && !windows

package xio

import "os"

func pinUnlinkPath(string) *os.File { return nil }
