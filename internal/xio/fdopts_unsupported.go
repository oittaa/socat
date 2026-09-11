//go:build darwin || windows

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"os"
)

func ApplyFDOptions(f *os.File, s addrconfig.Address) error {
	return ApplyFDOptionsSkip(f, s, FDSkip{})
}

func ApplyFDOptionsSkip(f *os.File, s addrconfig.Address, skip FDSkip) error {
	return applyFDLifecycleToFile(f, s, skip)
}
