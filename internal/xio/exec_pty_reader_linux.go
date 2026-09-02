//go:build linux

package xio

import (
	"io"
	"os"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func execPTYMasterReader(master, slave *os.File, s parse.Spec, _ <-chan struct{}) (io.Reader, func(), error) {
	logx.CloseQuiet(slave)
	r, err := ptyMasterReader(master, s)
	return r, nil, err
}
