//go:build e2e && darwin

package e2e_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

func writeSOCATIPEnvScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "print-socat-ip.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$SOCAT_IP_DSTADDR\"\nprintf '%s\\n' \"$SOCAT_IP_IF\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func startDarwinAncillaryRecv(t *testing.T, args ...string) *testProcess {
	t.Helper()
	return startDarwinAncillaryRecvIO(t, nil, args...)
}

func startDarwinAncillaryRecvIO(t *testing.T, stdout io.Writer, args ...string) *testProcess {
	t.Helper()
	cmd := exec.Command(socatBin(t), args...)
	if stdout != nil {
		cmd.Stdout = stdout
	}
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if proc.cmd.Process != nil {
			_ = proc.cmd.Process.Kill()
		}
		<-proc.done
	})
	return proc
}

func processDiag(proc *testProcess, stdout *lockedBuffer) string {
	err, exited := proc.status()
	state := "running"
	if exited {
		state = fmt.Sprintf("exited err=%v", err)
	}
	out := ""
	if stdout != nil {
		out = fmt.Sprintf(" stdout=%q", stdout.String())
	}
	return state + out + " stderr=" + proc.stderr.String()
}

func sendUntil(t *testing.T, timeout time.Duration, send func() error, ready func() bool, diag func() string, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	if err := send(); err != nil {
		t.Fatal(err)
	}
	for {
		if ready() {
			return
		}
		select {
		case <-done:
			if ready() {
				return
			}
			t.Fatalf("receiver exited before ancillary delivery; %s", diag())
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for ancillary delivery; %s", diag())
			}
			_ = send()
		}
	}
}

func darwinAncillaryLogged(stderr, wantIF string) bool {
	return (strings.Contains(stderr, "ancillary message: IP_RECVDSTADDR: dstaddr=127.0.0.1") ||
		strings.Contains(stderr, "IP_RECVDSTADDR: 127.0.0.1")) &&
		(strings.Contains(stderr, "ancillary message: IP_RECVIF: if="+wantIF) ||
			strings.Contains(stderr, "IP_RECVIF: "+wantIF))
}

func TestDarwinIPRecvdstaddrRecvifUDP(t *testing.T) {
	bin := socatBin(t)
	wantIF := testutil.IPv4LoopbackInterface(t)
	t.Run("log", func(t *testing.T) {
		port := freeUDPPort(t)
		proc := startDarwinAncillaryRecv(t, "-d", "-d", "-d", "-u",
			fmt.Sprintf("UDP4-RECV:%d,reuseaddr,ip-recvdstaddr,ip-recvif", port),
			"STDOUT")
		waitUDPListen(t, port, 2*time.Second, proc.cmd)
		send := func() error {
			c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			_, err = c.Write([]byte("XYZ"))
			return err
		}
		sendUntil(t, 3*time.Second, send, func() bool {
			return darwinAncillaryLogged(proc.stderr.String(), wantIF)
		}, func() string { return processDiag(proc, nil) }, proc.done)
	})
	t.Run("env", func(t *testing.T) {
		port := freeUDPPort(t)
		script := writeSOCATIPEnvScript(t)
		outPath := filepath.Join(t.TempDir(), "env.out")
		out, err := os.Create(outPath)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-u",
			fmt.Sprintf("UDP4-RECVFROM:%d,reuseaddr,ip-recvdstaddr,ip-recvif", port),
			"EXEC:"+script)
		cmd.Stdout = out
		proc, err := startTestProcess(cmd)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = out.Close()
			if proc.cmd.Process != nil {
				_ = proc.cmd.Process.Kill()
			}
			<-proc.done
		})
		waitUDPListen(t, port, 2*time.Second, proc.cmd)
		send := func() error {
			c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			_, err = c.Write([]byte("XYZ"))
			return err
		}
		sendUntil(t, 3*time.Second, send, func() bool {
			b, err := os.ReadFile(outPath)
			if err != nil {
				return false
			}
			got := strings.Split(strings.TrimSpace(string(b)), "\n")
			return len(got) >= 2 && got[0] == "127.0.0.1" && got[1] == wantIF
		}, func() string { return processDiag(proc, nil) }, proc.done)
	})
}
