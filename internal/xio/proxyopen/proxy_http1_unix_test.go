//go:build linux || darwin

package proxyopen

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestPROXYHTTP1BufferedDescriptorOptions(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	peer, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(peer, "HTTP/1.0 200 OK\r\n\r\npayload"); err != nil {
		t.Fatal(err)
	}
	conn, err := proxyHTTP1Handshake(client, addrconfig.Proxy{}, "192.0.2.1", 443, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := conn.(*prefixConn); !ok || string(p.prefix) != "payload" {
		t.Fatal("response did not exercise buffered payload")
	}
	spec, err := parse.ParseSpec("PROXY:h:h:9,cloexec=0,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := xio.SetupConnectedStream(mustAddr(t, spec), relay.NetStream{Conn: conn})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			t.Errorf("cloexec flags=%d err=%v", flags, err)
		}
		size, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err != nil || size < 65536 {
			t.Errorf("send buffer=%d err=%v", size, err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("payload"))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != "payload" {
		t.Fatalf("buffered payload=%q err=%v", got, err)
	}
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatalf("CONNECT peer did not reach EOF after half-close: %v", err)
	}
}
