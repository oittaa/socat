package netopen

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestOneshotForkConnShortReadDropsRemainder(t *testing.T) {
	c := newOneshotForkConn([]byte("abcd"), nil, nil, nil, nil, nil, nil, nil)
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = c.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("remainder n=%d err=%v want EOF", n, err)
	}
}

func TestOneshotForkConnEmptyFirstIsEOF(t *testing.T) {
	c := newOneshotForkConn(nil, nil, nil, nil, nil, nil, nil, nil)
	n, err := c.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
	}
}

func TestOneshotForkConnHidesSharedListener(t *testing.T) {
	var c any = &oneshotForkConn{}
	if _, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("oneshot fork must not implement syscall.Conn")
	}
	if _, ok := c.(interface{ NetConn() net.Conn }); ok {
		t.Fatal("oneshot fork must not expose NetConn")
	}
}

func TestOneshotForkConnCloseDoesNotCloseParent(t *testing.T) {
	parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	c := newOneshotForkConn(nil, parent.LocalAddr(), nil, nil, nil, nil, nil, nil)
	for i, err := range concurrentCloses(t, c.Close, 16) {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if err := parent.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("oneshot Close closed parent: %v", err)
	}
}
