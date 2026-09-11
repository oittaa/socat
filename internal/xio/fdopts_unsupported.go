//go:build darwin || windows

package xio

import (
	"os"

	"github.com/oittaa/socat/internal/parse"
)

func ApplyFDOptions(f *os.File, s parse.Spec) error {
	return ApplyFDOptionsSkip(f, s, FDSkip{})
}

func ApplyFDOptionsSkip(f *os.File, s parse.Spec, skip FDSkip) error {
	return applyFDLifecycleToFile(f, s, skip)
}
