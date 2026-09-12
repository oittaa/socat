package tunopen

import (
	"context"
	"strings"
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

func TestINTERFACEOpenUsesTypedName(t *testing.T) {
	spec, err := parse.ParseSpec("INTERFACE:lo")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Config.Network.InterfaceName != "lo" {
		t.Fatalf("InterfaceName=%q", prepared.Config.Network.InterfaceName)
	}
	prepared.Config.Params = nil
	o, err := xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, nil)
	if o != nil {
		t.Cleanup(func() { _ = o.Close() })
	}
	if err != nil && strings.Contains(err.Error(), "requires interface name") {
		t.Fatalf("open used Params after typed name was decoded: %v", err)
	}
}
