//go:build e2e && unix

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

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
			path := e2eUnixSocketPath(t, "target.sock")
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

func e2eUnixSocketPath(t *testing.T, name string) string {
	t.Helper()
	return testutil.UnixSocketPath(t, name)
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
