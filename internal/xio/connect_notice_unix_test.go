//go:build linux || darwin

package xio_test

import (
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestUNIXConnectSuccessLoggedAtNotice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dgram   bool
		level   logx.Level
		visible bool
	}{
		{"stream visible", false, logx.Debug, true},
		{"stream hidden below notice", false, logx.Warning, false},
		{"datagram visible", true, logx.Debug, true},
		{"datagram hidden below notice", true, logx.Warning, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx(t)
			path := testutil.UnixSocketPath(t, "srv.sock")
			spec := "UNIX-CONNECT:" + path
			var peerCh <-chan string
			if tc.dgram {
				ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = ln.Close() })
				spec += ",socktype=" + strconv.Itoa(syscall.SOCK_DGRAM)
			} else {
				ln, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = ln.Close() })
				peerCh = acceptRemote(t, ln)
			}

			g, buf := loggedSession(tc.level)
			o, err := xio.OpenChannel(ctx, mustParse(t, spec), xio.ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if peerCh != nil {
				waitAddr(t, ctx, peerCh)
			}
			assertEndpointLevel(t, buf.String(), path, tc.visible)
		})
	}
}
