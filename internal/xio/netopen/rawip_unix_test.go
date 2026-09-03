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
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
	}
}

func TestRawIPSessionConnEmptyFirstDatagram(t *testing.T) {
	r := &rawIPSessionConn{firstPending: true}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
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

func TestSkipIPv4HeaderIfPresent(t *testing.T) {
	t.Parallel()
	headerOnly := make([]byte, 20)
	headerOnly[0] = 0x45
	headerOnly[3] = 20
	if got := skipIPv4HeaderIfPresent(headerOnly, 20); got != 0 {
		t.Fatalf("header-only n=%d want 0", got)
	}

	withPayload := make([]byte, 25)
	withPayload[0] = 0x45
	withPayload[3] = 25
	copy(withPayload[20:], []byte("hello"))
	if got := skipIPv4HeaderIfPresent(withPayload, 25); got != 5 || string(withPayload[:5]) != "hello" {
		t.Fatalf("payload n=%d data=%q", got, withPayload[:got])
	}

	v6 := make([]byte, 40)
	v6[0] = 0x60
	if got := skipIPv4HeaderIfPresent(v6, 40); got != 40 {
		t.Fatalf("IPv6 n=%d want 40", got)
	}

	short := []byte{0x45, 0, 0, 20}
	if got := skipIPv4HeaderIfPresent(short, len(short)); got != len(short) {
		t.Fatalf("short n=%d want %d", got, len(short))
	}

	mismatch := make([]byte, 20)
	mismatch[0] = 0x45
	mismatch[3] = 40
	if got := skipIPv4HeaderIfPresent(mismatch, 20); got != 20 {
		t.Fatalf("length mismatch n=%d want 20", got)
	}
}

func TestAfterRawIPRecv(t *testing.T) {
	t.Parallel()
	// kernelN is supplied here. TestIP4HeaderOnlyNoAncillaryIsEOF exercises
	// the real IPv4 ancillary-disabled read, where ReadFrom would already
	// report n=0 after stripping the header.
	n, err := afterRawIPRecv(0, 0, nil, 16)
	if n != 0 || err != nil {
		t.Fatalf("kernel empty n=%d err=%v want 0, nil", n, err)
	}
	n, err = afterRawIPRecv(0, 20, nil, 16)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("header-only n=%d err=%v want EOF", n, err)
	}
	n, err = afterRawIPRecv(4, 24, nil, 16)
	if n != 4 || err != nil {
		t.Fatalf("payload n=%d err=%v", n, err)
	}
	sentinel := errors.New("recv")
	n, err = afterRawIPRecv(0, 0, sentinel, 16)
	if n != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("error n=%d err=%v", n, err)
	}
}

func TestIP4RecvHidesSyscallConn(t *testing.T) {
	t.Parallel()
	recv := &rawIPFilteredRecv{}
	if _, ok := any(recv).(syscall.Conn); ok {
		t.Fatal("IP4-RECV must not implement syscall.Conn; relay poll then waits on the SOCK_RAW fd instead of ReadMsg")
	}
	if _, ok := any(recv).(interface{ NetConn() net.Conn }); !ok {
		t.Fatal("IP4-RECV must expose NetConn for option lifecycle")
	}
}
