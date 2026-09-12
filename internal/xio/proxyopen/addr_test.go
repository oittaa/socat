package proxyopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func mustAddr(t testing.TB, spec parse.Spec) addrconfig.Address {
	t.Helper()
	if spec.Type == "" {
		config, err := addrconfig.Decode(spec, addrconfig.Facts{})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.Config
}
