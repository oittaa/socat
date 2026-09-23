package xio

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

var execNoFork func(ctx context.Context, peer relay.Stream, config addrconfig.Address, g *Global, mode Mode) error

func RegisterExecNoFork(fn func(context.Context, relay.Stream, addrconfig.Address, *Global, Mode) error) {
	execNoFork = fn
}

func runExecNoFork(ctx context.Context, peer relay.Stream, config addrconfig.Address, g *Global, mode Mode) error {
	if execNoFork == nil {
		return fmt.Errorf("EXEC address is not registered")
	}
	return execNoFork(ctx, peer, config, g, mode)
}
