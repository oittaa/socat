//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWaitTCPListenDelayedBind(t *testing.T) {
	addr, port := idleTCP4Port(t)
	proc, release := startGatedListenProcess(t, "tcp4", addr)
	requireGatedListenWait(t, proc, "tcp4", addr, func() error {
		return waitTCPTestProcess(proc, port, 2*time.Second)
	}, release)
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
	addr, port := idleUDP4Port(t)
	proc, release := startGatedListenProcess(t, "udp4", addr)
	requireGatedListenWait(t, proc, "udp4", addr, func() error {
		return waitUDPTestProcess(proc, port, 2*time.Second)
	}, release)
}

func requireGatedListenWait(t *testing.T, proc *testProcess, network, addr string, wait func() error, release func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := waitUntil(ctx, proc, func() (bool, error) {
		return strings.Contains(proc.stderr.String(), "gated"), nil
	}); err != nil {
		t.Fatalf("helper did not take the listen gate: %v stderr=%s", err, proc.stderr.String())
	}
	errc := make(chan error, 1)
	go func() { errc <- wait() }()
	owns, err := processListens(proc.cmd.Process.Pid, network, addr)
	if err != nil {
		t.Fatal(err)
	}
	if owns {
		t.Fatal("child listened before gate release")
	}
	select {
	case err := <-errc:
		t.Fatalf("wait returned before bind: %v stderr=%s", err, proc.stderr.String())
	default:
	}
	release()
	if err := <-errc; err != nil {
		t.Fatalf("delayed bind: %v stderr=%s", err, proc.stderr.String())
	}
}

func idleTCP4Port(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	requirePortIdle(t, "tcp4", addr)
	return addr, port
}

func idleUDP4Port(t *testing.T) (string, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	requirePortIdle(t, "udp4", addr)
	return addr, port
}

func requirePortIdle(t *testing.T, network, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := waitUntil(ctx, nil, func() (bool, error) {
		occupied, err := portOccupied(ctx, network, addr)
		if err != nil {
			return false, err
		}
		return !occupied, nil
	})
	if err != nil {
		t.Fatalf("port %s still occupied after close: %v", addr, err)
	}
}
