//go:build darwin || windows

package netopen

import (
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
