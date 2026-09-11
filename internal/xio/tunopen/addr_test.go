package tunopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func mustAddr(t testing.TB, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := xio.OpeningConfig(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
