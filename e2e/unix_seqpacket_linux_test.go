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

	cmd := exec.Command(bin, "UNIX-LISTEN:"+path+",so-type="+socktype, "PIPE")
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := waitUntil(ctx, proc, func() (bool, error) {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if info.Mode()&os.ModeSocket == 0 {
			return false, nil
		}
		if _, exited := proc.status(); exited {
			return false, processExitedWhileWaiting(proc)
		}
		return true, nil
	}); err != nil {
		t.Fatalf("timeout waiting for UNIX socket %s: %s", path, proc.stderr.String())
	}

	cliCtx, cliCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cliCancel()
	payload := "real seqpacket echo\n"
	cli := exec.CommandContext(cliCtx, bin, "-", "UNIX-CONNECT:"+path+",socktype="+socktype)
	cli.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cli.Stdout = &stdout
	cli.Stderr = &stderr
	if err := cli.Run(); err != nil {
		t.Fatalf("client: %v server=%s client=%s", err, proc.stderr.String(), stderr.String())
	}
	if stdout.String() != payload {
		t.Fatalf("echo=%q want %q server=%s client=%s", stdout.String(), payload, proc.stderr.String(), stderr.String())
	}
}
