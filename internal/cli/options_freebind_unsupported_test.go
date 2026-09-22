//go:build darwin || windows

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestIPFreebindRejectedOffLinux(t *testing.T) {
	spec := "TCP4-LISTEN:1,ip-freebind,ip-transparent"
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareChannel(ch)
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("%s: error=%v", spec, err)
	}
}
