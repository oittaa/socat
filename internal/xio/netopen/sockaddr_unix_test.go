//go:build linux || darwin

package netopen

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func mustSocketSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPackRawSockaddrLayouts(t *testing.T) {
	ipv4 := []byte{0x00, 0x50, 127, 0, 0, 1}
	sa, err := packRawSockaddr(unix.AF_INET, ipv4)
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	switch runtime.GOOS {
	case "linux":
		want = []byte{2, 0, 0x00, 0x50, 127, 0, 0, 1}
	case "darwin":
		want = []byte{8, 2, 0x00, 0x50, 127, 0, 0, 1}
	default:
		t.Fatalf("unexpected GOOS %s", runtime.GOOS)
	}
	if !bytes.Equal(sa.buf, want) {
		t.Fatalf("AF_INET short %x want %x", sa.buf, want)
	}

	padded := append(append([]byte{}, ipv4...), 1, 2, 3, 4, 5, 6, 7, 8)
	sa, err = packRawSockaddr(unix.AF_INET, padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa.buf[len(sa.buf)-8:], padded[6:]) {
		t.Fatalf("AF_INET padding %x", sa.buf)
	}

	flow := []byte{
		0x01, 0xbb,
		0x12, 0x34, 0x56, 0x78,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x05, 0x00, 0x00, 0x00,
	}
	sa, err = packRawSockaddr(unix.AF_INET6, flow)
	if err != nil {
		t.Fatal(err)
	}
	hdr := 2
	if runtime.GOOS == "darwin" {
		if sa.buf[0] != 28 || sa.buf[1] != byte(unix.AF_INET6) {
			t.Fatalf("AF_INET6 hdr %x", sa.buf[:2])
		}
	} else if sa.buf[0] != byte(unix.AF_INET6) || sa.buf[1] != 0 {
		t.Fatalf("AF_INET6 hdr %x", sa.buf[:2])
	}
	if !bytes.Equal(sa.buf[hdr:], flow) {
		t.Fatalf("AF_INET6 data %x want %x", sa.buf[hdr:], flow)
	}

	unixPath := []byte{'/', 't', 'm', 'p', 0, 'x'}
	sa, err = packRawSockaddr(unix.AF_UNIX, unixPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sa.buf, unixPath) {
		t.Fatalf("AF_UNIX dropped interior NUL: %x", sa.buf)
	}

	sa, err = packRawSockaddr(16, []byte{0x00})
	if err != nil {
		t.Fatal(err)
	}
	if len(sa.buf) != hdr+1 {
		t.Fatalf("unknown family len=%d", len(sa.buf))
	}
}

func TestParseSocketStreamCallBase0AndOptions(t *testing.T) {
	ipv4 := "x00007f000001"
	tests := []struct {
		raw                string
		domain, typ, proto int
	}{
		{"SOCKET-CONNECT:2:0:" + ipv4, unix.AF_INET, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:0x2:0x0:" + ipv4, unix.AF_INET, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:02:0:" + ipv4, unix.AF_INET, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:2:0:" + ipv4 + ",socktype=2", unix.AF_INET, unix.SOCK_DGRAM, 0},
		{"SOCKET-CONNECT:2:0:" + ipv4 + ",so-type=0x2", unix.AF_INET, unix.SOCK_DGRAM, 0},
		{"SOCKET-CONNECT:2:0:" + ipv4 + ",pf=10", unix.AF_INET6, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:2:0:" + ipv4 + ",protocol-family=ip6", unix.AF_INET6, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:2:6:" + ipv4 + ",socktype=2,pf=0xa", 10, unix.SOCK_DGRAM, 6},
		{"SOCKET-CONNECT::0:" + ipv4, unix.AF_INET, unix.SOCK_STREAM, 0},
		{"SOCKET-CONNECT:16:0:x00", 16, unix.SOCK_STREAM, 0},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			c, err := parseSocketStreamCall(mustSocketSpec(t, tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if c.domain != tc.domain || c.typ != tc.typ || c.proto != tc.proto {
				t.Fatalf("domain/type/proto=%d/%d/%d want %d/%d/%d",
					c.domain, c.typ, c.proto, tc.domain, tc.typ, tc.proto)
			}
		})
	}
}

func TestParseSocketDgramCallOverrides(t *testing.T) {
	c, err := parseSocketDgramCall(mustSocketSpec(t, "SOCKET-SENDTO:2:2:17:x00007f000001,pf=ip6,socktype=1"))
	if err != nil {
		t.Fatal(err)
	}
	if c.domain != unix.AF_INET6 || c.typ != unix.SOCK_STREAM || c.proto != 17 {
		t.Fatalf("got %+v", c)
	}
}

func TestSocketConnectUnknownDomainCallsSocket(t *testing.T) {
	_, err := openSocketConnect(context.Background(), mustSocketSpec(t, "SOCKET-CONNECT:99:0:x00"), xio.ModeRDWR, nil)
	if err == nil {
		t.Fatal("expected socket() failure")
	}
	if strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("rejected domain before socket(): %v", err)
	}
	if !strings.Contains(err.Error(), "socket:") {
		t.Fatalf("want socket: kernel error, got %v", err)
	}
}

func TestSocketIPv4ShortSockaddrBindIsEINVAL(t *testing.T) {
	_, err := openSocketListen(context.Background(), mustSocketSpec(t, "SOCKET-LISTEN:2:0:x00007f000001,reuseaddr"), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err == nil {
		t.Fatal("short sockaddr_in bind succeeded")
	}
	if !errors.Is(err, unix.EINVAL) && !strings.Contains(strings.ToLower(err.Error()), "invalid argument") {
		t.Fatalf("short bind err=%v want EINVAL", err)
	}
}

func TestBindConnectRawHonorCanceledContext(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	sa, err := packRawSockaddr(unix.AF_INET, []byte{0, 0, 127, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bindRaw(ctx, fd, sa); !errors.Is(err, context.Canceled) {
		t.Fatalf("bindRaw err=%v", err)
	}
	if err := connectRaw(ctx, fd, sa); !errors.Is(err, context.Canceled) {
		t.Fatalf("connectRaw err=%v", err)
	}
}

func ipv4SocketHex(port int, ip [4]byte) string {
	buf := make([]byte, 14)
	buf[0] = byte(port >> 8)
	buf[1] = byte(port)
	copy(buf[2:6], ip[:])
	return "x" + hex.EncodeToString(buf)
}

func TestSocketListenConnectIPv4(t *testing.T) {
	ctx := context.Background()
	listenData, err := xio.ParseSocatData(ipv4SocketHex(0, [4]byte{127, 0, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	sa, err := packRawSockaddr(unix.AF_INET, listenData)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := newSocket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindRaw(ctx, fd, sa); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	ln := &rawListener{fd: fd, domain: unix.AF_INET}
	t.Cleanup(func() { _ = ln.Close() })
	port := tcpPort(t, ln.Addr())

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		if err != nil && err != io.EOF {
			done <- err
			return
		}
		_, err = c.Write(buf[:n])
		done <- err
	}()

	client, err := openSocketConnect(ctx, mustSocketSpec(t, "SOCKET-CONNECT:2:0:"+ipv4SocketHex(port, [4]byte{127, 0, 0, 1})), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Stream.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := client.Stream.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q", buf[:n])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accept/echo timed out")
	}
}

func TestSocketConnectSocktypeDatagram(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	o, err := openSocketConnect(context.Background(), mustSocketSpec(t, "SOCKET-CONNECT:2:0:"+ipv4SocketHex(port, [4]byte{127, 0, 0, 1})+",socktype=2"), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if got := openedSOType(t, o.Stream); got != unix.SOCK_DGRAM {
		t.Fatalf("SO_TYPE=%d want SOCK_DGRAM", got)
	}
}

func openedSOType(t *testing.T, st relay.Stream) int {
	t.Helper()
	var conn syscall.Conn
	var walk func(any, int)
	walk = func(v any, depth int) {
		if conn != nil || v == nil || depth > 16 {
			return
		}
		if c, ok := v.(syscall.Conn); ok {
			conn = c
			return
		}
		switch x := v.(type) {
		case relay.FDStream:
			walk(x.R, depth+1)
			if conn == nil {
				walk(x.W, depth+1)
			}
		default:
			if u, ok := v.(interface{ UnwrapStream() relay.Stream }); ok {
				walk(u.UnwrapStream(), depth+1)
			}
		}
	}
	walk(st, 0)
	if conn == nil {
		t.Fatalf("no syscall.Conn on %T", st)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var typ int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		typ, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return typ
}
