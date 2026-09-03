//go:build e2e && darwin

package e2e_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func darwinIPv4LoopbackIF(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	want := net.IPv4(127, 0, 0, 1)
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.Equal(want) {
				return ifi.Name
			}
		}
	}
	t.Fatal("no interface has 127.0.0.1")
	return ""
}

func writeSOCATIPEnvScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "print-socat-ip.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$SOCAT_IP_DSTADDR\"\nprintf '%s\\n' \"$SOCAT_IP_IF\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireRootRawIP(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for raw IPv4")
	}
}

func startDarwinAncillaryRecv(t *testing.T, args ...string) *testProcess {
	t.Helper()
	cmd := exec.Command(socatBin(t), args...)
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

func sendUntil(t *testing.T, timeout time.Duration, send func() error, ready func() bool, stderr func() string, done <-chan struct{}) {
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
			t.Fatalf("receiver exited before ancillary delivery; stderr=%s", stderr())
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for ancillary delivery; stderr=%s", stderr())
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
	wantIF := darwinIPv4LoopbackIF(t)
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
		}, proc.stderr.String, proc.done)
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
		}, proc.stderr.String, proc.done)
	})
}

func TestDarwinIPRecvdstaddrRecvifRawIP(t *testing.T) {
	requireRootRawIP(t)
	bin := socatBin(t)
	wantIF := darwinIPv4LoopbackIF(t)
	const proto = 253
	t.Run("log", func(t *testing.T) {
		// IP4-RECVFROM receives the first packet in the opener (same path as
		// the env subtest). IP4-RECV waits in the transfer poll loop, which
		// on Darwin raw sockets can miss POLLIN and never ReadMsg.
		proc := startDarwinAncillaryRecv(t, "-d", "-d", "-d", "-u",
			fmt.Sprintf("IP4-RECVFROM:%d,ip-recvdstaddr,ip-recvif", proto),
			"STDOUT")
		send := func() error {
			cmd := exec.Command(bin, "-u", "-", fmt.Sprintf("IP4-SENDTO:127.0.0.1:%d", proto))
			cmd.Stdin = strings.NewReader("XYZ")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("send: %w: %s", err, out)
			}
			return nil
		}
		sendUntil(t, 5*time.Second, send, func() bool {
			return darwinAncillaryLogged(proc.stderr.String(), wantIF)
		}, proc.stderr.String, proc.done)
	})
	t.Run("env", func(t *testing.T) {
		script := writeSOCATIPEnvScript(t)
		outPath := filepath.Join(t.TempDir(), "env.out")
		out, err := os.Create(outPath)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-u",
			fmt.Sprintf("IP4-RECVFROM:%d,ip-recvdstaddr,ip-recvif", proto),
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
		send := func() error {
			scmd := exec.Command(bin, "-u", "-", fmt.Sprintf("IP4-SENDTO:127.0.0.1:%d", proto))
			scmd.Stdin = strings.NewReader("XYZ")
			outb, err := scmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("send: %w: %s", err, outb)
			}
			return nil
		}
		sendUntil(t, 5*time.Second, send, func() bool {
			b, err := os.ReadFile(outPath)
			if err != nil {
				return false
			}
			got := strings.Split(strings.TrimSpace(string(b)), "\n")
			return len(got) >= 2 && got[0] == "127.0.0.1" && got[1] == wantIF
		}, proc.stderr.String, proc.done)
	})
}
