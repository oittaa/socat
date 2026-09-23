//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPForkAddrDuringRebind(t *testing.T) {
	parsed := parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,fork,reuseaddr=0,accept-timeout=0.2")
	o, err := openUDP4Listen(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln := o.Listener()
	port := ln.Addr().(*net.UDPAddr).Port
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				got, ok := ln.Addr().(*net.UDPAddr)
				if !ok || got.Port != port {
					t.Errorf("Addr = %v, want port %d", ln.Addr(), port)
					return
				}
			}
		}
	}()
	_, err = ln.Accept()
	close(stop)
	<-done
	if !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("accept after close: %v", err)
	}
}
