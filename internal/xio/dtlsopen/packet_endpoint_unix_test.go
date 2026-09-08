//go:build linux || darwin

package dtlsopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestPacketizerExecNoforkStillRejectsDTLS(t *testing.T) {
	ctx, client, _ := packetEndpointPair(t, "")
	right, err := parse.ParseChannel("EXEC:cat,nofork")
	if err != nil {
		t.Fatal(err)
	}
	if err := xio.RunOpened(ctx, client, right, &xio.Global{}); err == nil {
		t.Fatal("nofork accepted an endpoint without a plaintext descriptor")
	}
}
