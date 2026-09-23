package fileopen

import (
	"context"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openChannel(ctx context.Context, ch parse.Channel, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	prepared, err := xio.PrepareChannel(ch)
	if err != nil {
		return nil, err
	}
	return xio.OpenPreparedChannel(ctx, prepared, mode, g)
}

func preparedSpec(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	prepared, err := xio.PrepareSpec(s)
	if err != nil {
		return nil, err
	}
	return xio.OpenPreparedSpec(ctx, prepared, mode, g)
}
