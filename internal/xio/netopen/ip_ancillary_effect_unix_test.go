//go:build unix

package netopen

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUDPConnectPktinfoIsNotNoop(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	port := server.LocalAddr().(*net.UDPAddr).Port

	spec, err := parse.ParseSpec("UDP-CONNECT:127.0.0.1:" + strconv.Itoa(port) + ",ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g := useGlobal()
	opened, err := openUDPConnectNetwork(ctx, spec, xio.ModeRDWR, g, "udp4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })

	local, ok := opened.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatalf("stream %T has no LocalAddr", opened.Stream)
	}
	if _, err := server.WriteTo([]byte("hi"), local.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if d, ok := opened.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	buf := make([]byte, 16)
	n, err := opened.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("payload=%q", buf[:n])
	}
	if g.SessionVars["IP_DSTADDR"] == "" && g.SessionVars["IP_LOCADDR"] == "" && g.SessionVars["IP_IF"] == "" {
		t.Fatalf("UDP-CONNECT ip-pktinfo was a no-op; session env=%v", g.SessionVars)
	}
}

func TestOpenSpecRejectsTCPRecvAncillary(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err=%v want not supported", err)
	}
}

func TestRawIPSendTTL(t *testing.T) {
	pc, err := net.ListenIP("ip4:255", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skipf("raw IP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	spec, err := parse.ParseSpec("IP4-RECV:255,ip-ttl=7")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyIPConnOpts(pc, spec, "ip4"); err != nil {
		t.Fatal(err)
	}
	raw, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if ttl != 7 {
		t.Fatalf("IP_TTL=%d want 7", ttl)
	}
}
