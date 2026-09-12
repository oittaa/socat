package dtlsopen

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/netopen"
)

func packetEndpointPair(t *testing.T, options string) (context.Context, *xio.Opened, net.Conn) {
	t.Helper()
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	// Allow full-size records even with a smaller default socket send buffer.
	ln, err := xio.OpenSpec(ctx, spec(t, "DTLS-LISTEN:0,bind=127.0.0.1,fork,dtls-mtu=20000,sndbuf=65536"+server), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+ln.Listener().Addr().String()+client+options), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p, err := ln.Listener().Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); _ = p.Close() })
	t.Cleanup(func() { stop() })
	return ctx, c, p
}

func TestPacketizerEndpointReadDeadline(t *testing.T) {
	_, client, _ := packetEndpointPair(t, "")
	relay.ConfigureStreamPair(client.Stream(), semanticTestStream{kind: relay.ByteStreamIO})
	if _, err := relay.SetStreamReadDeadline(client.Stream(), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Stream().Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %d, %v", n, err)
	}
}
