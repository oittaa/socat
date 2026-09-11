//go:build windows

package fileopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"

	"github.com/oittaa/socat/internal/xio"
)

func openAcceptFDNum(_ context.Context, s addrconfig.Address, _ xio.Mode, _ *xio.Global, _ int) (*xio.Opened, error) {
	return nil, fmt.Errorf("%s is not supported on windows", s.Type)
}
