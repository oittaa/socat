//go:build linux

package xio_test

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestStreamListenBacklogKernelQueue(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		spec func(backlog string) string
	}{
		{name: "tcp", spec: func(b string) string {
			return "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork" + backlogOpt(b)
		}},
		{name: "tls", spec: func(b string) string {
			return "TLS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + backlogOpt(b)
		}},
		{name: "ws", spec: func(b string) string {
			return "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork" + backlogOpt(b)
		}},
		{name: "wss", spec: func(b string) string {
			return "WSS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + backlogOpt(b)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertTCPListenSendQ(t, openForkListen(t, tc.spec("")).Listener.Addr(), xio.DefaultListenBacklog)
			assertTCPListenSendQ(t, openForkListen(t, tc.spec("1")).Listener.Addr(), 1)
			assertTCPListenSendQ(t, openForkListen(t, tc.spec("20")).Listener.Addr(), 20)
		})
	}
}

func assertTCPListenSendQ(t *testing.T, addr net.Addr, want int) {
	t.Helper()
	if got := testutil.TCPListenSendQ(t, addr); got != want {
		t.Fatalf("ss Send-Q=%d want %d (%s)", got, want, addr)
	}
}
