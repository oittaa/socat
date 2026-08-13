//go:build !linux && !darwin

package xio

import (
	"fmt"
	"os"
	"runtime"
)

func OpenPTYPair() (master, slave *os.File, err error) {
	return nil, nil, fmt.Errorf("PTY not supported on %s/%s (linux and darwin only)", runtime.GOOS, runtime.GOARCH)
}
