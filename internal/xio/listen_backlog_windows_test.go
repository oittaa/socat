//go:build windows

package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
)

func TestWindowsStreamListenUsesProviderDefault(t *testing.T) {
	openForkListen(t, "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork")
	path := testutil.UnixSocketPath(t, "b.sock")
	openForkListen(t, "UNIX-LISTEN:"+path+",unlink-early,fork")
}

func TestWindowsRejectsExplicitListenBacklog(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := testutil.UnixSocketPath(t, "b-explicit.sock")
	cases := map[string]string{
		"tcp":     "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=1",
		"tls":     "TLS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + ",backlog=1",
		"openssl": "OPENSSL-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + ",backlog=1",
		"ws":      "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=1",
		"wss":     "WSS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + ",backlog=1",
		"unix":    "UNIX-LISTEN:" + path + ",unlink-early,fork,backlog=1",
		"udp":     "UDP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=1",
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := openSpec(t, spec)
			if err == nil || !strings.Contains(err.Error(), "backlog: not supported on Windows") {
				t.Fatalf("error=%v want backlog unsupported error", err)
			}
		})
	}
}
