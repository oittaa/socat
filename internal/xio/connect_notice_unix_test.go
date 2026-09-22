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
	assertUNIXConnectEndpoint(t, logx.Debug, true)
}

func TestUNIXDgramConnectSuccessLoggedAtNotice(t *testing.T) {
	assertUNIXDgramConnectEndpoint(t, logx.Debug, true)
}

func TestUNIXDgramConnectSuccessHiddenBelowNotice(t *testing.T) {
	assertUNIXDgramConnectEndpoint(t, logx.Warning, false)
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

func assertUNIXDgramConnectEndpoint(t *testing.T, level logx.Level, visible bool) {
	t.Helper()
	ctx := testCtx(t)
	path := testutil.UnixSocketPath(t, "dgram.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	g, buf := loggedSession(level)
	spec := "UNIX-CONNECT:" + path + ",socktype=" + strconv.Itoa(syscall.SOCK_DGRAM)
	o, err := xio.OpenChannel(ctx, mustParse(t, spec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if visible {
		requireNoticeEndpoint(t, buf.String(), path)
		return
	}
	requireEndpointAbsent(t, buf.String(), path)
}
