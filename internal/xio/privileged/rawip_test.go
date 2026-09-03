//go:build privileged && (linux || darwin)

package privileged_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	_ "github.com/oittaa/socat/internal/xio/netopen"
)

func mustParseChannel(t *testing.T, address string) parse.Channel {
	t.Helper()
	channel, err := parse.ParseChannel(address)
	if err != nil {
		t.Fatal(err)
	}
	return channel
}

func TestIP4RecvEndCloseIdleTimeoutCancels(t *testing.T) {
	ctx, g := t.Context(), &xio.Global{}
	// Keep ownership of the socket so cleanup can unblock a regressed transfer.
	left, err := xio.OpenChannel(ctx, mustParseChannel(t, "IP4-RECV:251,bind=127.0.0.1"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })
	right, err := xio.OpenChannel(ctx, mustParseChannel(t, "OPEN:/dev/null"), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = right.Close() })

	done := make(chan error, 1)
	go func() {
		done <- relay.Transfer(ctx, left.EffectiveStream(), right.EffectiveStream(), relay.Config{
			LeftToRight: true,
			IdleTimeout: 100 * time.Millisecond,
			NoCloseLeft: true, // end-close keeps the shared socket open
		})
	}()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IP4-RECV,end-close idle timeout hung; SetReadDeadline was not forwarded")
	}
}
