package netopen

import (
	"context"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

// dialRequest is the shared connect context for TCP-like dials in this
// package. Destination and bind addresses stay as explicit parameters.
type dialRequest struct {
	ctx     context.Context
	network string
	timeout time.Duration
	config  addrconfig.Address
	g       *xio.Global
	control func(network, address string, c syscall.RawConn) error
	lowport bool
}

func (r dialRequest) withTimeout() (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return r.ctx, func() {}
	}
	return context.WithTimeout(r.ctx, r.timeout)
}
