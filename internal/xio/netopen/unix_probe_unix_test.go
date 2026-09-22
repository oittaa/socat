//go:build linux || darwin

package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenClassicAddressProbeFails(t *testing.T) {
	ch, err := parse.ParseChannel("UNIX-LISTEN:::::")
	if err != nil {
		return
	}
	_, err = xio.PrepareSpec(*ch.Single)
	if err == nil || !strings.Contains(err.Error(), "wrong number of parameters (5 instead of 1)") {
		t.Fatalf("UNIX-LISTEN::::: err=%v", err)
	}
}
