//go:build linux || darwin

package xio_test

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestUNIXConnectSuccessLoggedAtNotice(t *testing.T) {
	assertUNIXConnectEndpoint(t, logx.Notice, true)
}

func TestUNIXConnectSuccessHiddenBelowNotice(t *testing.T) {
	assertUNIXConnectEndpoint(t, logx.Warning, false)
}

func assertUNIXConnectEndpoint(t *testing.T, level logx.Level, visible bool) {
	t.Helper()
	ctx := testCtx(t)
	path := testutil.UnixSocketPath(t, "srv.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	peerCh := acceptRemote(t, ln)

	g, buf := loggedSession(level)
	o, err := xio.OpenChannel(ctx, mustParse(t, "UNIX-CONNECT:"+path), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	waitAddr(t, ctx, peerCh)
	if visible {
		requireNoticeEndpoint(t, buf.String(), path)
		return
	}
	requireEndpointAbsent(t, buf.String(), path)
}
