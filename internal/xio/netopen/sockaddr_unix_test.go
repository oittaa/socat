//go:build linux || darwin

package netopen

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
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

func TestParseSocketDgramCallOverrides(t *testing.T) {
	prepared, err := xio.PrepareSpec(mustSocketSpec(t, "SOCKET-SENDTO:2:2:17:x00007f000001,pf=ip6,socktype=1"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := socketCallFromConfig(prepared.Config)
	if err != nil {
		t.Fatal(err)
	}
	if c.domain != unix.AF_INET6 || c.typ != unix.SOCK_STREAM || c.proto != 17 {
		t.Fatalf("got %+v", c)
	}

	prepared, err = xio.PrepareSpec(mustSocketSpec(t, "SOCKET-SENDTO::2:0:x00007f000001,so-protocol=17"))
	if err != nil {
		t.Fatal(err)
	}
	c, err = socketCallFromConfig(prepared.Config)
	if err != nil {
		t.Fatal(err)
	}
	if c.domain != 0 || c.typ != unix.SOCK_DGRAM || c.proto != 17 {
		t.Fatalf("empty domain so-protocol got %+v", c)
	}
}

func TestSocketConnectUnknownDomainCallsSocket(t *testing.T) {
	_, err := xio.OpenSpec(context.Background(), mustSocketSpec(t, "SOCKET-CONNECT:99:0:x00"), xio.ModeRDWR, nil)
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
	_, err := xio.OpenSpec(context.Background(), mustSocketSpec(t, "SOCKET-LISTEN:2:0:x00007f000001,reuseaddr"), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
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
