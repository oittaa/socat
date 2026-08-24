//go:build e2e && windows

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var opErr error
				if err := c.Control(func(fd uintptr) {
					h := windows.Handle(fd)
					// Go's listener defaults set SO_REUSEADDR first; exclusive
					// bind only works after clearing it.
					_ = windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_REUSEADDR, 0)
					opErr = windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_EXCLUSIVEADDRUSE, 1)
				}); err != nil {
					return err
				}
				return opErr
			},
		}
		pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
		if err != nil {
			// Exclusive bind failed: the server already holds the port.
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
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == windows.STILL_ACTIVE
}
