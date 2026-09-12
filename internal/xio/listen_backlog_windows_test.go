//go:build windows

package xio_test

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestWindowsStreamListenUsesProviderDefault(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openForkListen(t, "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork")
	openForkListen(t, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork")
	openForkListen(t, "TLS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert="+cert)
	path := testutil.UnixSocketPath(t, "b.sock")
	openForkListen(t, "UNIX-LISTEN:"+path+",unlink-early,fork")
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
	if o.Kind() != xio.KindListen || o.Listener() == nil {
		t.Fatalf("Kind=%v listener=%v want KindListen", o.Kind(), o.Listener())
	}
	return o
}
