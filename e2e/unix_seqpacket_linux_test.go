//go:build e2e && linux

package e2e_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUnixSeqpacketEcho(t *testing.T) {
	bin := socatBin(t)
	path := e2eUnixSocketPath(t, "seqpacket.sock")
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
