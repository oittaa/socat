//go:build darwin

package netopen

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

// requireSessionDstAndIf checks the destination and interface recorded for
// this session. Both stay empty when the recv options are ignored.
func requireSessionDstAndIf(t *testing.T, g *xio.Global) {
	t.Helper()
	wantIF := testutil.IPv4LoopbackInterface(t)
	if got := g.SessionVar("IP_DSTADDR"); got != "127.0.0.1" {
		t.Fatalf("IP_DSTADDR=%q", got)
	}
	if got := g.SessionVar("IP_IF"); got != wantIF {
		t.Fatalf("IP_IF=%q want %s", got, wantIF)
	}
}

func TestUDP4RecvRecordsDestinationAndInterface(t *testing.T) {
	g := useGlobal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	spec, err := parse.ParseSpec("UDP4-RECV:0,bind=127.0.0.1,ip-recvdstaddr,ip-recvif")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recv(ctx, mustAddr(t, spec), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	la, ok := o.Stream().(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("UDP4-RECV stream has no local address")
	}
	ua, ok := la.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local addr %T", la.LocalAddr())
	}
	writeTo(t, listenUDP4Probe(t), "XYZ", ua)
	got, err := readDgram(t, o.Stream(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "XYZ" {
		t.Fatalf("payload=%q", got)
	}
	requireSessionDstAndIf(t, g)
}

func TestIP4RecvRecordsDestinationAndInterface(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECV:%d,bind=127.0.0.1,ip-recvdstaddr,ip-recvif", rawIPTestProto))
	g := useGlobal()
	o, err := openIP4Recv(ctx, mustAddr(t, spec), xio.ModeRead, g)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	client, _ := dialLoopbackRawIP4(t, rawIPTestProto, net.IPv4(127, 0, 0, 1))
	got := waitRawRead(t, client, []byte("XYZ"), o.Stream())
	if !rawPacketCarries(got, []byte("XYZ")) {
		t.Fatalf("payload=%q", got)
	}
	requireSessionDstAndIf(t, g)
}
