//go:build linux

package execopen

import (
	"io"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func execPTYMasterReader(master, slave *os.File, config addrconfig.Terminal, _ <-chan struct{}) (io.Reader, func(), error) {
	logx.CloseQuiet(slave)
	r, err := xio.ConfiguredPTYMasterReader(master, config)
	return r, nil, err
}
