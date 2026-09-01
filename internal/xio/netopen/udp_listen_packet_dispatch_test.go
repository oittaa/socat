//go:build darwin || windows

package netopen

import (
	"net"
	"syscall"
	"testing"
)

func TestUDPDispatchConnExposesNetConnWithoutSyscallConn(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	conn := &udpDispatchConn{pc: pc}
	if got := conn.NetConn(); got != pc {
		t.Fatalf("NetConn() = %T %v, want listener UDP socket", got, got)
	}
	if _, ok := any(conn).(syscall.Conn); ok {
		t.Fatal("udpDispatchConn must not expose SyscallConn to relay polling")
	}
}
