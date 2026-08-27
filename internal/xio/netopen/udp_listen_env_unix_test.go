//go:build unix

package netopen

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDP4ListenWildcardEnvironmentUsesLocalRouteAddress(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	client, err := net.DialUDP("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 1, 0, 1)},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("loopback alias unavailable: %v", err)
	}
	defer func() { _ = client.Close() }()

	spec, err := parse.ParseSpec("UDP4-LISTEN:" + strconv.Itoa(port) + ",reuseaddr=0")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	opened := make(chan *xio.Opened, 1)
	errc := make(chan error, 1)
	go func() {
		o, err := openUDP4Listen(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _ = client.Write([]byte("env"))
		case err := <-errc:
			t.Fatal(err)
		case o := <-opened:
			defer func() { _ = o.Close() }()
			if g.PeerAddr != "127.1.0.1" {
				t.Fatalf("SOCAT_PEERADDR=%q want 127.1.0.1", g.PeerAddr)
			}
			if g.SockAddr != "127.0.0.1" {
				t.Fatalf("SOCAT_SOCKADDR=%q want 127.0.0.1", g.SockAddr)
			}
			return
		case <-ctx.Done():
			t.Fatal("timed out opening wildcard UDP listener")
		}
	}
}
