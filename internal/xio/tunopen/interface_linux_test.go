//go:build linux

package tunopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestINTERFACELoPreparesAndOpens(t *testing.T) {
	for _, text := range []string{"INTERFACE:lo", "IF:lo"} {
		t.Run(text, func(t *testing.T) {
			spec, err := parse.ParseSpec(text)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := xio.PrepareSpec(spec)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.Config.Network.Kind != addrconfig.AddressKindINTERFACE {
				t.Fatalf("kind=%v", prepared.Config.Network.Kind)
			}
			if prepared.Config.Network.TUNAddressSet {
				t.Fatal("INTERFACE name decoded as TUN prefix")
			}
			o, err := xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, nil)
			if err != nil {
				t.Skipf("requires AF_PACKET on lo: %v", err)
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
