package xio_test

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestOpenSpecCarriesChildrenShutup(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,child-shutup=2")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if opened.ChildrenShutup != 2 {
		t.Fatalf("ChildrenShutup=%d want 2", opened.ChildrenShutup)
	}
}
