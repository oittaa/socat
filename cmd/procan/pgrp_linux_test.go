//go:build linux

package main

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestForegroundProcessGroupMatchesPTYChild(t *testing.T) {
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })

	cmd := exec.Command("sh", "-c", "read -r line")
	cmd.Stdin = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	// Start completes after the controlling terminal is assigned. The child
	// stays alive waiting for input while we query its foreground group.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pg, err := foregroundProcessGroup(int(master.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if pg != cmd.Process.Pid {
		t.Fatalf("foreground process group = %d, want child PID %d", pg, cmd.Process.Pid)
	}
}
