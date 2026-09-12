//go:build linux

package xio

import (
	"io"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
)

func execPTYMasterReader(master, slave *os.File, config addrconfig.Terminal, _ <-chan struct{}) (io.Reader, func(), error) {
	logx.CloseQuiet(slave)
	r, err := configuredPTYMasterReader(master, config)
	return r, nil, err
}
