//go:build e2e && !windows

package e2e_test

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func waitUDPListen(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			time.Sleep(30 * time.Millisecond)
			return
		}
		_ = pc.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for UDP listen on %d", port)
}
