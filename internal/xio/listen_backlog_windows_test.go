//go:build windows

package xio_test

import (
	"testing"

	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
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
