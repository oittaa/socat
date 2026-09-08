//go:build darwin || windows

package netopen

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestUDPDispatchConnHidesSharedSocket(t *testing.T) {
	conn := &udpDispatchConn{}
	if _, ok := any(conn).(interface{ NetConn() net.Conn }); ok {
		t.Fatal("udpDispatchConn must not expose the shared listener through NetConn")
	}
	if _, ok := any(conn).(syscall.Conn); ok {
		t.Fatal("udpDispatchConn must not expose SyscallConn to relay polling")
	}
}

func TestUDPDispatchConnEmptyPacketIsEOF(t *testing.T) {
	conn := &udpDispatchConn{
		pending:     udpForkPacket{},
		havePending: true,
		done:        make(chan struct{}),
		packets:     make(chan udpForkPacket),
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-length Read = %d, %v; want 0, nil", n, err)
	}
	if !conn.havePending {
		t.Fatal("zero-length Read consumed the pending datagram")
	}
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty datagram Read = %d, %v; want 0, EOF", n, err)
	}
}
