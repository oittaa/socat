package xio_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func testGlobal() *xio.Global {
	return &xio.Global{BlockSize: 8192, Log: logx.New()}
}

func openSpec(t *testing.T, spec string) (*xio.Opened, error) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return xio.OpenSpec(context.Background(), s, xio.ModeRDWR, testGlobal())
}

func TestTCP4ClientBindEmptyHostConnectsOnLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan net.Conn, 1)
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	o, err := openSpec(t, fmt.Sprintf("TCP4:127.0.0.1:%d,bind=:0,ai-passive=0", port))
	if err != nil {
		t.Fatalf("client bind=:0,ai-passive=0: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	la, ok := o.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("stream has no LocalAddr")
	}
	got := la.LocalAddr().(*net.TCPAddr)
	if got == nil || got.IP == nil || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LocalAddr=%v want 127.0.0.1", got)
	}

	peer := <-accepted
	if peer == nil {
		t.Fatal("listener accept failed")
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := o.Stream.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ok" {
		t.Fatalf("peer read %q", buf)
	}
}

func TestTCP4ListenBindColonPortRejected(t *testing.T) {
	for _, spec := range []string{
		"TCP4-LISTEN:0,bind=:0",
		"TCP4-LISTEN:0,bind=:8080",
		"TCP4-LISTEN:0,bind=127.0.0.1:12345",
	} {
		o, err := openSpec(t, spec)
		if o != nil {
			_ = o.Close()
		}
		if err == nil {
			t.Fatalf("%s: opened; want reject", spec)
		}
	}
}

func TestUDP4DatagramBindEmptyHostUsesLoopback(t *testing.T) {
	o, err := openSpec(t, "UDP4-DATAGRAM:127.0.0.1:9,bind=:0,ai-passive=0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	la, ok := o.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("stream has no LocalAddr")
	}
	got := la.LocalAddr().(*net.UDPAddr)
	if got == nil || got.IP == nil || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LocalAddr=%v want 127.0.0.1", got)
	}
}
