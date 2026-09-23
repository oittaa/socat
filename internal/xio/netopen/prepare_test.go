package netopen

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

func openSpec(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	prepared, err := xio.PrepareSpec(s)
	if err != nil {
		return nil, err
	}
	return xio.OpenPreparedSpec(ctx, prepared, mode, g)
}

func runOpened(ctx context.Context, lo *xio.Opened, right parse.Channel, g *xio.Global) error {
	prepared, err := xio.PrepareChannel(right)
	if err != nil {
		if lo != nil {
			_ = lo.Close()
		}
		return err
	}
	return xio.RunOpenedPrepared(ctx, lo, prepared, g)
}
