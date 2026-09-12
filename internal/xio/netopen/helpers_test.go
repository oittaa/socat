package netopen

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func useGlobal() *xio.Global {
	return xio.NewSession(xio.Options{BlockSize: 8192, Linger: 200 * time.Millisecond}, logx.New())
}

func parseChannel(t *testing.T, spec string) parse.Channel {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}
