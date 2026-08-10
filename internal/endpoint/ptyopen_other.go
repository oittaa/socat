//go:build !linux && !darwin

package endpoint

import (
	"fmt"
	"os"
	"runtime"
)

func openPTYPair() (master, slave *os.File, err error) {
	return nil, nil, fmt.Errorf("PTY not supported on %s/%s (linux and darwin only)", runtime.GOOS, runtime.GOARCH)
}
