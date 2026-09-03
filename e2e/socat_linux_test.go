//go:build linux

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVersionHasPOSIXMQ(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_POSIXMQ 1")) {
		t.Fatalf("missing WITH_POSIXMQ 1:\n%s", out)
	}
	h := capabilityOutput(t, "-h")
	if !bytes.Contains(h, []byte("POSIXMQ-SEND")) {
		t.Fatalf("help missing POSIXMQ-SEND: %s", h)
	}
	hh := capabilityOutput(t, "-hh")
	for _, opt := range []string{"mq-prio", "mq-flush", "mq-maxmsg", "mq-msgsize"} {
		if !bytes.Contains(hh, []byte(" "+opt+" ")) {
			t.Fatalf("help missing %s:\n%s", opt, hh)
		}
	}
}

func TestPOSIXMQReadPrio(t *testing.T) {
	bin := socatBin(t)
	q := fmt.Sprintf("/socat-e2e-%d-%d", os.Getpid(), time.Now().UnixNano()%1e9)
	defer exec.Command(bin, "-u", "/dev/null", "POSIXMQ-SEND:"+q+",unlink-close").Run()

	msg0 := fmt.Sprintf("prio0-%d\n", time.Now().UnixNano())
	msg1 := fmt.Sprintf("prio1-%d\n", time.Now().UnixNano())
	c0 := exec.Command(bin, "-u", "STDIO", "POSIXMQ-SEND:"+q+",mq-prio=0,unlink-early")
	c0.Stdin = strings.NewReader(msg0)
	if out, err := c0.CombinedOutput(); err != nil {
		t.Fatalf("send0: %v %s", err, out)
	}
	c1 := exec.Command(bin, "-u", "STDIO", "POSIXMQ-SEND:"+q+",mq-prio=1")
	c1.Stdin = strings.NewReader(msg1)
	if out, err := c1.CombinedOutput(); err != nil {
		t.Fatalf("send1: %v %s", err, out)
	}
	rd := exec.Command(bin, "-u", "POSIXMQ-READ:"+q+",unlink-close", "STDIO")
	stdout, err := rd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	rd.Stderr = &stderr
	if err := rd.Start(); err != nil {
		t.Fatal(err)
	}
	want := msg1 + msg0
	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stdout, got)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			_ = rd.Process.Kill()
			_, _ = rd.Process.Wait()
			t.Fatalf("read POSIX MQ output: %v stderr=%s", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		_ = rd.Process.Kill()
		_, _ = rd.Process.Wait()
		t.Fatalf("timed out reading POSIX MQ output; stderr=%s", stderr.String())
	}
	_ = rd.Process.Kill()
	_, _ = rd.Process.Wait()
	if string(got) != want {
		t.Fatalf("got %q want %q stderr=%s", got, want, stderr.String())
	}
}

func TestVersionHasNAMESPACES(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_NAMESPACES 1")) {
		t.Fatalf("missing WITH_NAMESPACES 1:\n%s", out)
	}
	hh := capabilityOutput(t, "-hh")
	if !bytes.Contains(hh, []byte(" netns ")) {
		t.Fatalf("help missing netns:\n%s", hh)
	}
	h := capabilityOutput(t, "-h")
	if !bytes.Contains(h, []byte("--experimental")) {
		t.Fatalf("help missing --experimental:\n%s", h)
	}
}

func TestVersionHasSCTP(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_SCTP 1")) {
		t.Fatalf("missing WITH_SCTP 1:\n%s", out)
	}
	h := capabilityOutput(t, "-h")
	if !bytes.Contains(h, []byte("SCTP4-")) {
		t.Fatalf("help missing SCTP4-: %s", h)
	}
}

func TestVersionHasVSOCK(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_VSOCK 1")) {
		t.Fatalf("missing WITH_VSOCK 1:\n%s", out)
	}
	h := capabilityOutput(t, "-h")
	if !bytes.Contains(h, []byte("VSOCK-CONNECT:")) {
		t.Fatalf("help missing VSOCK-CONNECT: %s", h)
	}
	if !bytes.Contains(h, []byte("VSOCK-LISTEN:")) {
		t.Fatalf("help missing VSOCK-LISTEN: %s", h)
	}
}

func TestVSOCKListenAcceptTimeout(t *testing.T) {
	bin := socatBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, os.DevNull, "VSOCK-LISTEN:-1,accept-timeout=0.05")
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("VSOCK-LISTEN accept-timeout hung: %s", out)
	}
	if err != nil {
		t.Skipf("VSOCK-LISTEN not usable: %v: %s", err, out)
	}
}

func TestVSOCKListenPortZeroMatchesClassic(t *testing.T) {
	bin := socatBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, os.DevNull, "VSOCK-LISTEN:0,accept-timeout=0.05")
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("VSOCK-LISTEN:0 hung: %s", out)
	}
	if err == nil {
		t.Fatalf("VSOCK-LISTEN:0 succeeded; classic bind of port 0 is permission denied: %s", out)
	}
	msg := strings.ToLower(string(out))
	if strings.Contains(msg, "unknown") && strings.Contains(msg, "vsock") {
		t.Skipf("VSOCK not available: %s", out)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Fatalf("VSOCK-LISTEN:0 error %q does not mention permission denied", out)
	}
}
