//go:build linux

package netopen

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func skipIfNoSCTP(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("no kernel SCTP: %v", err)
	}
	_ = unix.Close(fd)
}

func TestSCTPOpenChannelListenTimeout(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("SCTP4-LISTEN:0,reuseaddr,bind=127.0.0.1,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	_, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("want accept timeout, got %v", err)
	}
}

func TestSCTPServiceNameHTTP(t *testing.T) {
	n, err := xio.ResolvePortNum("sctp4", "http")
	if err != nil {
		t.Fatal(err)
	}
	if n != 80 {
		t.Fatalf("http=%d", n)
	}
}

func TestSCTPConnectErrTreatsEstablishedEISCONNAsSuccess(t *testing.T) {
	if err := sctpConnectErr(nil, nil); err != nil {
		t.Fatalf("nil connect err: %v", err)
	}
	if err := sctpConnectErr(unix.EISCONN, func() error { return nil }); err != nil {
		t.Fatalf("established EISCONN: %v", err)
	}
	if err := sctpConnectErr(unix.EISCONN, func() error { return unix.EINVAL }); !errors.Is(err, unix.EISCONN) {
		t.Fatalf("unconnected EISCONN: %v", err)
	}
	if err := sctpConnectErr(unix.ECONNREFUSED, nil); err == nil || err.Error() != "Connection refused" {
		t.Fatalf("ECONNREFUSED: %v", err)
	}
}
