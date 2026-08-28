//go:build unix

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestRawIPListenPastSocketThenPrebindUnix(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf(
		"IP4-RECV:1,setsockopt-socket=%d:%d:1,setsockopt-listen=%d:%d:0",
		unix.SOL_SOCKET, unix.SO_KEEPALIVE, unix.SOL_SOCKET, unix.SO_KEEPALIVE,
	))
	if err != nil {
		t.Fatal(err)
	}
	var values []int
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.Opt == unix.SO_KEEPALIVE {
			values = append(values, c.IntValue)
		}
	})
	defer restore()
	c, err := listenRawIP(context.Background(), "ip4:1", "ip4", &net.IPAddr{IP: net.IPv4zero}, spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if len(values) != 2 || values[0] != 1 || values[1] != 0 {
		t.Fatalf("SO_KEEPALIVE values=%v want PASTSOCKET 1 then PREBIND 0", values)
	}
}

func TestRawIPRecvFromIsNotSyscallConn(t *testing.T) {
	var s any = &rawIPRecvFrom{}
	if _, ok := s.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("rawIPRecvFrom must not implement syscall.Conn; relay would poll an empty socket")
	}
	if _, ok := s.(interface{ NetConn() net.Conn }); !ok {
		t.Fatal("rawIPRecvFrom must expose NetConn for option lifecycle")
	}
}
