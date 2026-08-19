//go:build e2e && unix

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUnixSeqpacketEcho(t *testing.T) {
	bin := socatBin(t)
	path := filepath.Join(t.TempDir(), "seqpacket.sock")
	socktype := strconv.Itoa(syscall.SOCK_SEQPACKET)

	srv := exec.Command(bin, "UNIX-LISTEN:"+path+",so-type="+socktype, "PIPE")
	var srvErr bytes.Buffer
	srv.Stderr = &srvErr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	waitUnixSocket(t, path, &srvErr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	payload := "real seqpacket echo\n"
	cli := exec.CommandContext(ctx, bin, "-", "UNIX-CONNECT:"+path+",socktype="+socktype)
	cli.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cli.Stdout = &stdout
	cli.Stderr = &stderr
	if err := cli.Run(); err != nil {
		t.Fatalf("client: %v server=%s client=%s", err, srvErr.String(), stderr.String())
	}
	if stdout.String() != payload {
		t.Fatalf("echo=%q want %q server=%s client=%s", stdout.String(), payload, srvErr.String(), stderr.String())
	}
}

func TestUnixSocketTypeMismatchExitCode(t *testing.T) {
	bin := socatBin(t)
	seqpacket := strconv.Itoa(syscall.SOCK_SEQPACKET)
	tests := []struct {
		name    string
		listen  func(t *testing.T, path string) io.Closer
		address func(path string) string
	}{
		{name: "CONNECT_TO_DGRAM", listen: e2eListenUnixgram, address: func(path string) string { return "UNIX-CONNECT:" + path }},
		{name: "CONNECT_TO_SEQPACKET", listen: e2eListenUnixpacket, address: func(path string) string { return "UNIX-CONNECT:" + path }},
		{name: "SEQPACKET_TO_STREAM", listen: e2eListenUnixStream, address: func(path string) string { return "UNIX-CONNECT:" + path + ",socktype=" + seqpacket }},
		{name: "SEQPACKET_TO_DGRAM", listen: e2eListenUnixgram, address: func(path string) string { return "UNIX-CONNECT:" + path + ",socktype=" + seqpacket }},
		{name: "DGRAM_TO_STREAM", listen: e2eListenUnixStream, address: func(path string) string {
			return "UNIX-CONNECT:" + path + ",socktype=" + strconv.Itoa(syscall.SOCK_DGRAM)
		}},
		{name: "DGRAM_TO_SEQPACKET", listen: e2eListenUnixpacket, address: func(path string) string {
			return "UNIX-CONNECT:" + path + ",socktype=" + strconv.Itoa(syscall.SOCK_DGRAM)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "target.sock")
			listener := tt.listen(t, path)
			defer func() { _ = listener.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-u", "-", tt.address(path))
			cmd.Stdin = strings.NewReader("must fail\n")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("expected exit error, got %v stderr=%s", err, stderr.String())
			}
			if exitErr.ExitCode() != 1 {
				t.Fatalf("exit=%d want 1 stderr=%s", exitErr.ExitCode(), stderr.String())
			}
			if got := bytes.Count(stderr.Bytes(), []byte(" E ")); got != 1 {
				t.Fatalf("error messages=%d want 1 stderr=%s", got, stderr.String())
			}
		})
	}
}

func waitUnixSocket(t *testing.T, path string, stderr *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for UNIX socket %s: %s", path, stderr.String())
}

func e2eListenUnixStream(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func e2eListenUnixpacket(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.Listen("unixpacket", path)
	if err != nil {
		if errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SOCK_SEQPACKET is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return listener
}

func e2eListenUnixgram(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}
