//go:build e2e && linux

package e2e_test

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestAcceptFDSystemdSocketActivate(t *testing.T) {
	if _, err := exec.LookPath("systemd-socket-activate"); err != nil {
		t.Fatal("systemd-socket-activate not available")
	}
	bin := socatBin(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command("systemd-socket-activate", "-l", fmt.Sprintf("127.0.0.1:%d", port), "--inetd", bin, "-t", "2", "ACCEPT-FD:0", "PIPE")
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)
	waitTCPListen(t, proc, port, 5*time.Second)
	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, proc.stderr.String())
	}
	defer func() { _ = cli.Close() }()
	payload := []byte("systemd-accept-fd")
	if _, err := cli.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("echo: %v stderr=%s", err, proc.stderr.String())
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q stderr=%s", got, payload, proc.stderr.String())
	}
}
