package sockopt_test

import (
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
