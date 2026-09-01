//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
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

func TestRawIPSessionConnIsNotSyscallConn(t *testing.T) {
	var s any = &rawIPSessionConn{}
	if _, ok := s.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("rawIPSessionConn must not implement syscall.Conn; relay would poll the shared listener")
	}
}

func TestRawIPRecvFromEmptyFirstDatagram(t *testing.T) {
	r := &rawIPRecvFrom{firstPending: true, closeEOF: true}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || err != nil {
		t.Fatalf("empty first n=%d err=%v", n, err)
	}
	n, err = r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after empty first n=%d err=%v want EOF", n, err)
	}
}

func TestRawIPSessionConnEmptyFirstDatagram(t *testing.T) {
	r := &rawIPSessionConn{firstPending: true}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || err != nil {
		t.Fatalf("empty first n=%d err=%v", n, err)
	}
	n, err = r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after empty first n=%d err=%v want EOF", n, err)
	}
}

func TestRawIPRecvFromShortReadDropsRemainder(t *testing.T) {
	r := &rawIPRecvFrom{first: []byte("abcd"), firstPending: true, closeEOF: true}
	buf := make([]byte, 1)
	n, err := r.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = r.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("remainder n=%d err=%v want EOF", n, err)
	}
}
