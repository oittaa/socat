package tlsopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func tryAddr(spec parse.Spec) (addrconfig.Address, error) {
	return xio.OpeningConfig(context.Background(), spec)
}

func mustAddr(t testing.TB, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := tryAddr(spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
