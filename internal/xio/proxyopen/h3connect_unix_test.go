//go:build linux || darwin

package proxyopen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestListenH3PacketAppliesMembershipExactlyOnce(t *testing.T) {
	var iface string
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range ifaces {
		if candidate.Flags&net.FlagUp != 0 && candidate.Flags&net.FlagMulticast != 0 {
			iface = candidate.Name
			if candidate.Flags&net.FlagLoopback != 0 {
				break
			}
		}
	}
	if iface == "" {
		t.Skip("no multicast interface")
	}
	spec, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,ip-add-membership=224.0.0.6:" + iface + ",sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	var membershipCalls, lateCalls int
	restore := xio.SetSockoptTestHook(func(call xio.SockoptCall) {
		if call.AsInt {
			lateCalls++
		} else {
			membershipCalls++
		}
	})
	t.Cleanup(restore)
	pc, network, err := listenH3Packet(context.Background(), spec, &xio.Global{}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if network != "udp4" {
		t.Fatalf("network=%q, want udp4", network)
	}
	if membershipCalls != 1 {
		t.Fatalf("HTTP/3 UDP membership setsockopt calls=%d, want exactly 1", membershipCalls)
	}
	if lateCalls != 1 {
		t.Fatalf("HTTP/3 UDP late setsockopt calls=%d, want exactly 1", lateCalls)
	}
}

func TestListenH3PacketAppliesMulticastTTL(t *testing.T) {
	spec, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,ip-multicast-ttl=9")
	if err != nil {
		t.Fatal(err)
	}
	var ttlCalls int
	restore := xio.SetSockoptTestHook(func(call xio.SockoptCall) {
		if !call.AsInt && len(call.Bytes) == 1 && call.Bytes[0] == 9 {
			ttlCalls++
		}
	})
	t.Cleanup(restore)
	pc, network, err := listenH3Packet(context.Background(), spec, &xio.Global{}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if network != "udp4" {
		t.Fatalf("network=%q, want udp4", network)
	}
	if ttlCalls != 1 {
		t.Fatalf("HTTP/3 UDP IP_MULTICAST_TTL setsockopt calls=%d, want 1", ttlCalls)
	}
}

func TestListenH3PacketAppliesAppendToTransportOnce(t *testing.T) {
	spec, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,append")
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		if op == "F_SETFL" {
			calls++
		}
	})
	t.Cleanup(restore)
	pc, _, err := listenH3Packet(context.Background(), spec, &xio.Global{}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if calls != 1 {
		t.Fatalf("HTTP/3 transport append calls=%d want 1", calls)
	}
}

func TestListenH3PacketLowport(t *testing.T) {
	spec, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,lowport,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := listenH3Packet(context.Background(), spec, &xio.Global{}, "127.0.0.1")
	if err != nil {
		if !strings.Contains(err.Error(), "lowport: cannot bind a port in 640-1023") {
			t.Fatalf("lowport bind: %v", err)
		}
		return
	}
	t.Cleanup(func() { _ = pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if port < xio.LowportMin || port > xio.LowportMax {
		t.Fatalf("HTTP/3 local port=%d want %d-%d", port, xio.LowportMin, xio.LowportMax)
	}
}

func TestListenH3PacketExplicitSourceportOverridesLowport(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	spec, err := parse.ParseSpec(fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,lowport,bind=127.0.0.1,sourceport=%d",
		port,
	))
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := listenH3Packet(context.Background(), spec, &xio.Global{}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if got := pc.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Fatalf("HTTP/3 local port=%d want explicit sourceport %d", got, port)
	}
}
