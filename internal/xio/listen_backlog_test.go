package xio_test

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func backlogOpt(value string) string {
	if value == "" {
		return ""
	}
	return ",backlog=" + value
}

func openForkListen(t *testing.T, spec string) *xio.Opened {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), s, xio.ModeRDWR, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen || o.Listener == nil {
		t.Fatalf("Kind=%v listener=%v want KindListen", o.Kind, o.Listener)
	}
	return o
}
