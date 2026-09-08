package xio_test

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func testGlobal() *xio.Global {
	return &xio.Global{BlockSize: 8192, Log: logx.New()}
}

func openSpec(t *testing.T, spec string) (*xio.Opened, error) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return xio.OpenSpec(context.Background(), s, xio.ModeRDWR, testGlobal())
}
