//go:build windows

package fileopen

import (
	"fmt"
	"os"
)

const oNonblock = 0

func mkfifo(string, uint32) error { return fmt.Errorf("named pipe FIFO is not supported on Windows") }

func socketpairFiles() (*os.File, *os.File, error) {
	return nil, nil, fmt.Errorf("SOCKETPAIR is not supported on Windows")
}

func clearNonblock(*os.File) {}
