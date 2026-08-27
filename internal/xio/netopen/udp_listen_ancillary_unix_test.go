//go:build unix

package netopen

import (
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestDialUDPSessionAppliesPastSocketIPOptions(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	spec, err := parse.ParseSpec("UDP4-LISTEN:0,reuseaddr,ip-ttl=42,ip-recvttl=1")
	if err != nil {
		t.Fatal(err)
	}
	child, err := dialUDPSession(
		t.Context(),
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		server.LocalAddr().(*net.UDPAddr),
		spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })

	raw, err := child.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl, recvTTL int
	var sockErr error
	controlErr := raw.Control(func(fd uintptr) {
		ttl, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		if sockErr == nil {
			recvTTL, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL)
		}
	})
	if err := errors.Join(controlErr, sockErr); err != nil {
		t.Fatal(err)
	}
	if ttl != 42 {
		t.Fatalf("child IP_TTL=%d want 42", ttl)
	}
	if recvTTL == 0 {
		t.Fatal("child IP_RECVTTL is disabled")
	}
}
