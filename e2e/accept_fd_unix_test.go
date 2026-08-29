//go:build e2e && (linux || darwin)

package e2e_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
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
	tcpln := ln.(*net.TCPListener)
	f, err := tcpln.File()
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-t", "2", "ACCEPT-FD:3", "PIPE")
	cmd.ExtraFiles = []*os.File{f}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		_ = ln.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	_ = ln.Close()
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	waitTCPListen(t, port, 5*time.Second)

	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, stderr.String())
	}
	defer func() { _ = cli.Close() }()
	payload := []byte("extrafiles-accept-fd")
	if _, err := cli.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("echo: %v stderr=%s", err, stderr.String())
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q stderr=%s", got, payload, stderr.String())
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
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		_ = ln.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	_ = ln.Close()
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	waitTCPListen(t, port, 5*time.Second)
	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, stderr.String())
	}
	defer func() { _ = cli.Close() }()
	if _, err := cli.Write([]byte("alias")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("echo: %v stderr=%s", err, stderr.String())
	}
	if string(got) != "alias" {
		t.Fatalf("got %q stderr=%s", got, stderr.String())
	}
}

func TestAcceptFDSystemdSocketActivate(t *testing.T) {
	if _, err := exec.LookPath("systemd-socket-activate"); err != nil {
		t.Skip("systemd-socket-activate not available")
	}
	bin := socatBin(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command("systemd-socket-activate", "-l", fmt.Sprintf("127.0.0.1:%d", port), "--inetd", bin, "-t", "2", "ACCEPT-FD:0", "PIPE")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	waitTCPListen(t, port, 5*time.Second)
	cli, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v stderr=%s", err, stderr.String())
	}
	defer func() { _ = cli.Close() }()
	payload := []byte("systemd-accept-fd")
	if _, err := cli.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("echo: %v stderr=%s", err, stderr.String())
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q stderr=%s", got, payload, stderr.String())
	}
}
