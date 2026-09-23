package execopen

import (
	"context"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func decodeAddress(spec parse.Spec) (addrconfig.Address, error) {
	prepared, err := xio.PrepareSpec(spec)
	if err == nil {
		return prepared.Config, nil
	}
	config, err2 := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type})
	if err2 != nil {
		return addrconfig.Address{}, err
	}
	return config, nil
}

func mustDecodeAddress(t *testing.T, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := decodeAddress(spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func replaceAtPath(t *testing.T, path string, contents []byte, perm os.FileMode) {
	t.Helper()
	other := path + ".new"
	if err := os.WriteFile(other, contents, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
}

func OpenSpec(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	prepared, err := xio.PrepareSpec(s)
	if err != nil {
		return nil, err
	}
	return xio.OpenPreparedSpec(ctx, prepared, mode, g)
}

func OpenChannel(ctx context.Context, ch parse.Channel, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	prepared, err := xio.PrepareChannel(ch)
	if err != nil {
		return nil, err
	}
	return xio.OpenPreparedChannel(ctx, prepared, mode, g)
}
