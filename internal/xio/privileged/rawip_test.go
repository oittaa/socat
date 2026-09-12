//go:build privileged && (linux || darwin)

package privileged_test

import (
	"context"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	_ "github.com/oittaa/socat/internal/xio/netopen"
)

func TestIPRecvEOFDoesNotLinger(t *testing.T) {
	right, err := parse.ParseChannel("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"IP4-RECV:253", "IP6-RECV:253"} {
		t.Run(address, func(t *testing.T) {
			left, err := parse.ParseChannel(address)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			g := xio.NewSession(xio.Options{Linger: time.Hour}, nil) // EOF must finish the relay, not the linger timer.
			if err := xio.Run(ctx, left, right, g); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatal("opposite EOF left the raw-IP receiver blocked")
			}
		})
	}
}
