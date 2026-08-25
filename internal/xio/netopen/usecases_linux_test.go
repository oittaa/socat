//go:build linux

package netopen

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func TestSCTP4ListenConnectUseCase(t *testing.T) {
	if !xio.FeatureSCTP {
		t.Skip("SCTP not enabled")
	}
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lo, err := xio.OpenChannel(ctx, parseChannel(t, "SCTP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1"), xio.ModeRDWR, useGlobal())
	if err != nil {
		if strings.Contains(err.Error(), "protocol not supported") {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("SCTP4-LISTEN did not return a listener")
	}
	go func() { _ = xio.RunOpened(ctx, lo, parseChannel(t, "PIPE"), useGlobal()) }()
	ta, ok := lo.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("SCTP listen addr %T", lo.Listener.Addr())
	}
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "SCTP4:127.0.0.1:"+strconv.Itoa(ta.Port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		if strings.Contains(err.Error(), "protocol not supported") {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("sctp-use"))
}
