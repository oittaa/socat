//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestWaitTCPListenDelayedBind(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	proc := startDelayedListenProcess(t, "tcp4", addr, 80*time.Millisecond)
	if err := waitTCPTestProcess(proc, port, 2*time.Second); err != nil {
		t.Fatalf("delayed bind: %v", err)
	}
	cli, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
}

func TestWaitTCPListenDetectsEarlyExit(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)
	requireWaitFailedAfterChildExit(t, waitTCPTestProcess(proc, port, 2*time.Second))
}

func requireWaitFailedAfterChildExit(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected wait to fail after child exit")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait timed out instead of detecting child exit: %v", err)
	}
	if !errors.Is(err, errProcessExitedWhileWaiting) {
		t.Fatalf("error=%v want process exited while waiting", err)
	}
}

func TestWaitTCPListenTimesOutAndCleansUp(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	proc := startHoldStdioProcess(t)
	err = waitTCPTestProcess(proc, port, 80*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want deadline exceeded", err)
	}
	if _, exited := proc.status(); exited {
		t.Fatal("timeout wait should leave the child running")
	}
}

func TestWaitTCPListenUnrelatedPortOccupation(t *testing.T) {
	bin := socatBin(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	proc, err := startTestProcess(exec.Command(bin,
		fmt.Sprintf("TCP4-LISTEN:%d,bind=127.0.0.1", port),
		"PIPE",
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)
	if err := waitTCPTestProcess(proc, port, 2*time.Second); err == nil {
		t.Fatal("expected wait to fail when another process owns the port")
	}
}

func TestWaitUDPListenDelayedBind(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	proc := startDelayedListenProcess(t, "udp4", addr, 80*time.Millisecond)
	if err := waitUDPTestProcess(proc, port, 2*time.Second); err != nil {
		t.Fatalf("delayed UDP bind: %v", err)
	}
}
