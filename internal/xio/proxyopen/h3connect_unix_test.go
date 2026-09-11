//go:build linux || darwin

package proxyopen

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestListenH3PacketLowport(t *testing.T) {
	spec, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,lowport,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := listenH3Packet(context.Background(), mustAddr(t, spec), &xio.Global{}, addrconfig.HostFromText("127.0.0.1"))
	if err != nil {
		if !strings.Contains(err.Error(), "lowport: cannot bind a port in 640-1023") {
			t.Fatalf("lowport bind: %v", err)
		}
		return
	}
	t.Cleanup(func() { _ = pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if port < xio.LowportMin || port > xio.LowportMax {
		t.Fatalf("HTTP/3 local port=%d want %d-%d", port, xio.LowportMin, xio.LowportMax)
	}
}
