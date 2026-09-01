//go:build linux

package netopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketListenBacklogKernelQueue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backlog string
		want    int
	}{
		{name: "default", want: xio.DefaultListenBacklog},
		{name: "one", backlog: "1", want: 1},
		{name: "twenty", backlog: "20", want: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := "SOCKET-LISTEN:2:0:" + ipv4SocketHex(0, [4]byte{127, 0, 0, 1}) + ",reuseaddr,fork"
			if tc.backlog != "" {
				spec += ",backlog=" + tc.backlog
			}
			o, err := openSocketListen(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if o.Listener == nil {
				t.Fatal("missing listener")
			}
			if got := testutil.TCPListenSendQ(t, o.Listener.Addr()); got != tc.want {
				t.Fatalf("ss Send-Q=%d want %d", got, tc.want)
			}
		})
	}
}
