//go:build unix

package netopen

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
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
	spec, err := parse.ParseSpec("IP4-RECV:255,ip-ttl=7")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenRawIP(t.Context(), "ip4:255", &net.IPAddr{IP: net.IPv4zero}, spec)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
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

func skipIfRawIPPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("SOCK_RAW requires CAP_NET_RAW: %v", err)
	}
}

func TestRawIPSendtoAppliesTTLBeforeConnect(t *testing.T) {
	var ttlDuring int
	var sawControl bool
	testHookAfterRawIPPastSocket = func(network, address string, c syscall.RawConn) error {
		sawControl = true
		return c.Control(func(fd uintptr) {
			ttlDuring, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		})
	}
	t.Cleanup(func() { testHookAfterRawIPPastSocket = nil })

	spec, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:255,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, err := openIPSendtoNetwork(ctx, spec, xio.ModeRDWR, useGlobal(), "ip4")
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if !sawControl {
		t.Fatal("raw-IP DialControl did not run; PH_PASTSOCKET options must apply before connect")
	}
	if ttlDuring != 64 {
		t.Fatalf("IP_TTL during Control=%d want 64 (before connect)", ttlDuring)
	}
}

func TestRawIPRecvAppliesTTLBeforeBind(t *testing.T) {
	var ttlDuring int
	var recvTTLDuring int
	var sawControl bool
	testHookAfterRawIPPastSocket = func(network, address string, c syscall.RawConn) error {
		sawControl = true
		return c.Control(func(fd uintptr) {
			ttlDuring, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
			recvTTLDuring, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL)
		})
	}
	t.Cleanup(func() { testHookAfterRawIPPastSocket = nil })

	spec, err := parse.ParseSpec("IP4-RECV:255,ip-recvttl=1,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened, err := openIPRecvNetwork(ctx, spec, xio.ModeRead, useGlobal(), "ip4", false)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if !sawControl {
		t.Fatal("raw-IP ListenControl did not run; PH_PASTSOCKET options must apply before bind")
	}
	if recvTTLDuring == 0 {
		t.Fatal("IP_RECVTTL unset during Control; classic applies recv and send together before bind")
	}
	if ttlDuring != 64 {
		t.Fatalf("IP_TTL during Control=%d want 64 (before bind)", ttlDuring)
	}
}
