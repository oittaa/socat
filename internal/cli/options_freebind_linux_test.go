//go:build linux

package cli

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestIPFreebindAcceptedOnLinux(t *testing.T) {
	spec := "TCP4-LISTEN:1,ip-freebind,ip-transparent"
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xio.PrepareChannel(ch); err != nil {
		t.Fatal(err)
	}
}
