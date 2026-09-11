package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func tryAddr(spec parse.Spec) (addrconfig.Address, error) {
	if spec.Type == "" {
		return addrconfig.Decode(spec, addrconfig.Facts{})
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		return addrconfig.Address{}, err
	}
	return prepared.Config, nil
}

func mustAddr(t testing.TB, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := tryAddr(spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
