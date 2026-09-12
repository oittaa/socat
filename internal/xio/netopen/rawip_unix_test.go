//go:build linux || darwin

package netopen

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

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

func TestRawIPRecvFromEmptyFirstDatagram(t *testing.T) {
	r := &rawIPRecvFrom{first: newFirstPacket(nil)}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
	}
}

func TestRawIPRecvFromShortReadDropsRemainder(t *testing.T) {
	r := &rawIPRecvFrom{first: newFirstPacket([]byte("abcd"))}
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

func TestIP4RecvHidesSyscallConn(t *testing.T) {
	t.Parallel()
	recv := &rawIPFilteredRecv{}
	if _, ok := any(recv).(syscall.Conn); ok {
		t.Fatal("IP4-RECV must not implement syscall.Conn; relay poll then waits on the SOCK_RAW fd instead of ReadMsg")
	}
	if _, ok := any(recv).(interface{ NetConn() net.Conn }); !ok {
		t.Fatal("IP4-RECV must expose NetConn for option lifecycle")
	}
	if _, ok := any(recv).(interface{ SetReadDeadline(time.Time) error }); !ok {
		t.Fatal("IP4-RECV must forward SetReadDeadline so end-close cancellation can unblock Read")
	}
}
