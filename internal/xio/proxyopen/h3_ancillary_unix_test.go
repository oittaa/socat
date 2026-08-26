//go:build unix

package proxyopen

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sys/unix"
)

func packetConnIPTTL(t *testing.T, pc net.PacketConn) int {
	t.Helper()
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return ttl
}

func packetConnIPv6UnicastHops(t *testing.T, pc net.PacketConn) int {
	t.Helper()
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var hops int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		hops, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return hops
}

func TestH3CONNECTAppliesIPTTLOnPacketConn(t *testing.T) {
	certs := writeTrustCerts(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	tlsCfg := serverH3TLS(certs)
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })

	var ttl int
	testHookH3PacketConn = func(c net.PacketConn) {
		ttl = packetConnIPTTL(t, c)
	}
	t.Cleanup(func() { testHookH3PacketConn = nil })

	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%s,verify=0,ip-ttl=64",
		port,
	))
	if ttl != 64 {
		t.Fatalf("HTTP/3 UDP IP_TTL=%d want 64 (ListenControl PH_PASTSOCKET)", ttl)
	}
}

func TestH3CONNECTAppliesIPv6UnicastHopsOnPacketConn(t *testing.T) {
	certs := writeTrustCerts(t)
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	tlsCfg := serverH3TLS(certs)
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })

	var hops int
	testHookH3PacketConn = func(c net.PacketConn) {
		hops = packetConnIPv6UnicastHops(t, c)
	}
	t.Cleanup(func() { testHookH3PacketConn = nil })

	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:[::1]:[::1]:9,http-version=3,proxyport=%s,verify=0,ipv6-unicast-hops=9",
		port,
	))
	if hops != 9 {
		t.Fatalf("HTTP/3 UDP IPV6_UNICAST_HOPS=%d want 9", hops)
	}
}

func serverH3TLS(certs trustCerts) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certs.serverTLS},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
}
