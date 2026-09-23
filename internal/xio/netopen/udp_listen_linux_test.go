//go:build linux

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPSecondBindWithReuseaddrSucceeds(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1,reuseaddr", port)), port)
	if err != nil {
		t.Fatalf("second UDP-LISTEN,reuseaddr: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}

func TestUDP6ForkReuseaddrZeroClosedSessionKeepsListening(t *testing.T) {
	parsed := parseUDPSpec(t, "UDP6-LISTEN:0,bind=[::1],fork,reuseaddr=0,accept-timeout=0.2")
	o, err := openUDP6Listen(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	client, err := net.DialUDP("udp6", nil, o.Listener().Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	conn, err := o.Listener().Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err = o.Listener().Accept(); !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("accept after close: %v", err)
	}
}
