//go:build linux || darwin

package netopen

import (
	"context"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketRecvfromForkHasWrapDial(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("SOCKET-RECVFROM:2:2:17:x00007f0000010000000000000000,reuseaddr,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter() != nil {
		t.Fatal("SOCKET-RECVFROM,fork must filter in Accept only")
	}
	assertWrapDialReadbytes(t, o)
}

func TestSocketListenForkHasWrapDial(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("SOCKET-LISTEN:2:0:x00007f0000010000000000000000,reuseaddr,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter() == nil {
		t.Fatal("SOCKET-LISTEN must install PeerFilter")
	}
	assertWrapDialReadbytes(t, o)
}
