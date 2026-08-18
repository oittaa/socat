//go:build windows

package xio

import (
	"fmt"
	"os"
)

func unixSocketpairLogged(*Global) (*os.File, *os.File, error) {
	return nil, nil, fmt.Errorf("socketpair is not available on Windows")
}
