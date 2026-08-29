//go:build linux || darwin

package proxyopen

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestH2CONNECTAppliesAppendToTransportOnce(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		if op == "F_SETFL" {
			calls++
		}
	})
	t.Cleanup(restore)
	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0,append",
		port,
	))
	if calls != 1 {
		t.Fatalf("HTTP/2 transport append calls=%d want 1", calls)
	}
}
