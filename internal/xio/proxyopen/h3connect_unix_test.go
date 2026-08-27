//go:build unix

package proxyopen

import (
	"context"
	"net"
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
