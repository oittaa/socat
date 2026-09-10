//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

var errProcessExitedWhileWaiting = errors.New("process exited while waiting")

const listenProbeInterval = 20 * time.Millisecond

func TestMain(m *testing.M) {
	switch os.Getenv("SOCAT_E2E_HELPER") {
	case "delayed-listen":
		os.Exit(runDelayedListenHelper())
	case "hold-stdio":
		os.Exit(runHoldStdioHelper())
	}
	os.Exit(m.Run())
}

func waitUntil(ctx context.Context, p *testProcess, probe func() (bool, error)) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	first := true
	for {
		if !first {
			select {
			case <-ctx.Done():
				if p != nil {
					select {
					case <-p.done:
						return processExitedWhileWaiting(p)
					default:
					}
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
		first = false
		ok, err := probe()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if p != nil {
			select {
			case <-p.done:
				return processExitedWhileWaiting(p)
			default:
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(listenProbeInterval)
	}
}

func processExitedWhileWaiting(p *testProcess) error {
	err, _ := p.status()
	if err != nil {
		return fmt.Errorf("%w: %w", errProcessExitedWhileWaiting, err)
	}
	return errProcessExitedWhileWaiting
}

func waitTCPTestProcess(p *testProcess, port int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return waitPortReady(ctx, p, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
}

func waitUDPTestProcess(p *testProcess, port int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return waitPortReady(ctx, p, "udp4", fmt.Sprintf("127.0.0.1:%d", port))
}

func waitPortReady(ctx context.Context, p *testProcess, network, addr string) error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return fmt.Errorf("listen wait requires a child process")
	}
	pid := p.cmd.Process.Pid
	return waitUntil(ctx, p, func() (bool, error) {
		// Exclusive occupancy probes bind the port. Check child ownership first
		// so a delayed bind is not raced by the waiter.
		owns, err := processListens(pid, network, addr)
		if err != nil || !owns {
			return owns, err
		}
		occupied, err := portOccupied(ctx, network, addr)
		if err != nil {
			return false, err
		}
		if !occupied {
			return false, nil
		}
		if _, exited := p.status(); exited {
			return false, processExitedWhileWaiting(p)
		}
		return true, nil
	})
}

func waitTCPListen(t *testing.T, p *testProcess, port int, timeout time.Duration) {
	t.Helper()
	if err := waitTCPTestProcess(p, port, timeout); err != nil {
		t.Fatal(err)
	}
}

func waitFileExists(ctx context.Context, path string, p *testProcess) error {
	return waitUntil(ctx, p, func() (bool, error) {
		_, err := os.Stat(path)
		if err == nil {
			if p != nil {
				if _, exited := p.status(); exited {
					return false, processExitedWhileWaiting(p)
				}
			}
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	})
}

func waitFileEqual(ctx context.Context, path string, want []byte, p *testProcess) error {
	return waitUntil(ctx, p, func() (bool, error) {
		got, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return bytes.Equal(got, want), nil
	})
}

func waitFileContainsCount(ctx context.Context, path string, needle []byte, want int, p *testProcess) error {
	return waitUntil(ctx, p, func() (bool, error) {
		got, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return bytes.Count(got, needle) >= want, nil
	})
}

func runSCTPEcho(ctx context.Context, bin string, args []string, payload []byte) (stdout, stderr []byte, err error) {
	pr, pw := io.Pipe()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = pr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = pw.Close()
		return nil, nil, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, nil, err
	}
	writeErr := make(chan error, 1)
	go func() {
		_, werr := pw.Write(payload)
		writeErr <- werr
	}()
	need := bytes.TrimSpace(payload)
	got := make([]byte, 0, len(payload)+8)
	tmp := make([]byte, 256)
	for !bytes.Contains(got, need) {
		n, rerr := stdoutPipe.Read(tmp)
		got = append(got, tmp[:n]...)
		if rerr != nil {
			_ = pw.Close()
			_ = cmd.Wait()
			return got, errb.Bytes(), rerr
		}
	}
	_ = pw.Close()
	rest, _ := io.ReadAll(stdoutPipe)
	got = append(got, rest...)
	waitErr := cmd.Wait()
	if werr := <-writeErr; werr != nil && waitErr == nil {
		waitErr = werr
	}
	return got, errb.Bytes(), waitErr
}

func runDelayedListenHelper() int {
	network := os.Getenv("SOCAT_E2E_LISTEN_NET")
	addr := os.Getenv("SOCAT_E2E_LISTEN_ADDR")
	fmt.Fprintln(os.Stderr, "gated")
	buf := make([]byte, 1)
	if _, err := os.Stdin.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "delayed listen gate: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if strings.HasPrefix(network, "udp") {
		var pc net.PacketConn
		err := retryBusyBind(ctx, func() error {
			var lerr error
			pc, lerr = net.ListenPacket(network, addr)
			return lerr
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "delayed %s listen %s: %v\n", network, addr, err)
			return 1
		}
		defer func() { _ = pc.Close() }()
		readBuf := make([]byte, 1)
		_, _, _ = pc.ReadFrom(readBuf)
		return 0
	}
	var ln net.Listener
	err := retryBusyBind(ctx, func() error {
		var lerr error
		ln, lerr = net.Listen(network, addr)
		return lerr
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "delayed %s listen %s: %v\n", network, addr, err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	c, err := ln.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "delayed %s accept %s: %v\n", network, addr, err)
		return 1
	}
	_ = c.Close()
	return 0
}

func retryBusyBind(ctx context.Context, bind func() error) error {
	var last error
	timer := time.NewTimer(0)
	defer timer.Stop()
	first := true
	for {
		if !first {
			select {
			case <-ctx.Done():
				if last != nil {
					return last
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
		first = false
		err := bind()
		if err == nil {
			return nil
		}
		last = err
		if !testutil.BindBusy(err) {
			return err
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(listenProbeInterval)
	}
}

func runHoldStdioHelper() int {
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

func startGatedListenProcess(t *testing.T, network, addr string) (*testProcess, func()) {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Stdin = pr
	cmd.Env = append(os.Environ(),
		"SOCAT_E2E_HELPER=delayed-listen",
		"SOCAT_E2E_LISTEN_NET="+network,
		"SOCAT_E2E_LISTEN_ADDR="+addr,
	)
	p, err := startTestProcess(cmd)
	_ = pr.Close()
	if err != nil {
		_ = pw.Close()
		t.Fatal(err)
	}
	release := func() { _ = pw.Close() }
	t.Cleanup(func() {
		release()
		p.stop()
	})
	return p, release
}

func startHoldStdioProcess(t *testing.T) *testProcess {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SOCAT_E2E_HELPER=hold-stdio")
	cmd.Stdin = pr
	p, err := startTestProcess(cmd)
	_ = pr.Close()
	if err != nil {
		_ = pw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pw.Close()
		p.stop()
	})
	return p
}
