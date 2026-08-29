//go:build darwin

package xio

import "github.com/oittaa/socat/internal/parse"

// applyLinuxPHFDOption is a no-op off Linux. ApplyFDOptions already rejects
// enabled o-noatime / f-setpipe-sz / fs-* names on this GOOS.
func applyLinuxPHFDOption(int, parse.Option) error { return nil }
