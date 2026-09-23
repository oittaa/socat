//go:build windows

package execopen

import (
	"fmt"
	"os"
)

func OpenPTYPair() (master, slave *os.File, err error) {
	return nil, nil, fmt.Errorf("PTY is not supported on Windows")
}
