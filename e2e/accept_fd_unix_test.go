//go:build e2e && (linux || darwin)

package e2e_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestAcceptFDExtraFilesChild(t *testing.T) {
	bin := socatBin(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-t", "2", "ACCEPT-FD:3", "PIPE")
	cmd.ExtraFiles = []*os.File{f}
	proc, err := startTestProcess(cmd)
	if err != nil {
		_ = f.Close()
		_ = ln.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	_ = ln.Close()
	t.Cleanup(proc.stop)

	waitTCPListen(t, proc, port, 5*time.Second)

	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, proc.stderr.String())
	}
	defer func() { _ = cli.Close() }()
	payload := []byte("extrafiles-accept-fd")
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

func TestAcceptAliasExtraFilesChild(t *testing.T) {
	bin := socatBin(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-t", "2", "ACCEPT:3", "PIPE")
	cmd.ExtraFiles = []*os.File{f}
	proc, err := startTestProcess(cmd)
	if err != nil {
		_ = f.Close()
		_ = ln.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	_ = ln.Close()
	t.Cleanup(proc.stop)
	waitTCPListen(t, proc, port, 5*time.Second)
	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, proc.stderr.String())
	}
	defer func() { _ = cli.Close() }()
	if _, err := cli.Write([]byte("alias")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("echo: %v stderr=%s", err, proc.stderr.String())
	}
	if string(got) != "alias" {
		t.Fatalf("got %q stderr=%s", got, proc.stderr.String())
	}
}
