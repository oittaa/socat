//go:build linux || darwin

package netopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenClassicAddressProbeFails(t *testing.T) {
	ch, err := parse.ParseChannel("UNIX-LISTEN:::::")
	if err != nil {
		return
	}
	if _, err := openUnixListen(context.Background(), *ch.Single, xio.ModeRDWR, nil); err == nil {
		t.Fatal("UNIX-LISTEN::::: unexpectedly opened a listener")
	}
}
