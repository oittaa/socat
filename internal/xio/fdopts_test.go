package xio

import (
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
)

func ApplyFDOptions(f *os.File, s addrconfig.Address) error {
	return ApplyConfiguredFDOptions(f, s.File, FDSkip{})
}
