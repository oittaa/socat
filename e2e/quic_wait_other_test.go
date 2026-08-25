//go:build e2e && !windows

package e2e_test

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func waitUDPListen(t *testing.T, port int, timeout time.Duration, cmds ...*exec.Cmd) {
	t.Helper()
	if err := errWaitUDPListen(port, timeout, cmds...); err != nil {
		t.Fatal(err)
	}
}

func errWaitUDPListen(port int, timeout time.Duration, cmds ...*exec.Cmd) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		for _, cmd := range cmds {
			if !udpServerAlive(cmd) {
				return fmt.Errorf("UDP server exited before listening on %d", port)
			}
		}
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			time.Sleep(30 * time.Millisecond)
			return nil
		}
		_ = pc.Close()
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for UDP listen on %d", port)
}

func udpServerAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	// Signal(0) still succeeds for zombies. WNOHANG waitpid detects an
	// exited child without blocking; callers already ignore a later Wait.
	var status syscall.WaitStatus
	wpid, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WNOHANG, nil)
	if err != nil {
		return false
	}
	return wpid != cmd.Process.Pid
}
