package wsopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func mustAddr(tb testing.TB, spec parse.Spec) addrconfig.Address {
	tb.Helper()
	if spec.Type == "" {
		config, err := addrconfig.Decode(spec, addrconfig.Facts{})
		if err != nil {
			tb.Fatal(err)
		}
		return config
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		tb.Fatal(err)
	}
	return prepared.Config
}
