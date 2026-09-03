//go:build e2e && privileged && darwin

package privileged_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

// Only os/exec's stdout copier accesses the buffer until cmd.Wait completes.
type outputBarrier struct {
	buffer bytes.Buffer
	want   string
	ready  chan struct{}
}

func (w *outputBarrier) Write(p []byte) (int, error) {
	n, err := w.buffer.Write(p)
	if strings.Contains(w.buffer.String(), w.want) {
		select {
		case w.ready <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (w *outputBarrier) String() string { return w.buffer.String() }

func runRawIPReceiver(t *testing.T, wantOutput string, args ...string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	bin := os.Getenv("SOCAT")
	stdout := &outputBarrier{want: wantOutput, ready: make(chan struct{}, 1)}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	stop := func() {
		_ = cmd.Process.Kill()
		<-done
	}
	t.Cleanup(stop)

	// Retry opener packets until the receiver produces the expected output.
	// Output, not a sleep or a startup-log phrase, is the completion barrier.
	retry := time.NewTicker(20 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-stdout.ready:
			stop()
			return stdout.String(), stderr.String()
		case <-done:
			if strings.Contains(stdout.String(), wantOutput) {
				return stdout.String(), stderr.String()
			}
			t.Fatalf("receiver exited before delivery: %v; stdout=%q stderr=%s", waitErr, stdout.String(), stderr.String())
		case <-ctx.Done():
			stop()
			t.Fatalf("receiver timed out: stdout=%q stderr=%s", stdout.String(), stderr.String())
		case <-retry.C:
			send := exec.CommandContext(ctx, bin, "-u", "-", "IP4-SENDTO:127.0.0.1:253")
			send.Stdin = strings.NewReader("XYZ")
			if out, err := send.CombinedOutput(); err != nil {
				t.Fatalf("send: %v: %s", err, out)
			}
		}
	}
}

func TestDarwinIPRecvdstaddrRecvifRawIP(t *testing.T) {
	wantIF := testutil.IPv4LoopbackInterface(t)
	for _, address := range []string{"IP4-RECV", "IP4-RECVFROM"} {
		t.Run(address, func(t *testing.T) {
			_, stderr := runRawIPReceiver(t, "XYZ", "-d", "-d", "-d", "-u",
				address+":253,ip-recvdstaddr,ip-recvif", "STDOUT")
			hasDst := strings.Contains(stderr, "ancillary message: IP_RECVDSTADDR: dstaddr=127.0.0.1") ||
				strings.Contains(stderr, "IP_RECVDSTADDR: 127.0.0.1")
			hasIF := strings.Contains(stderr, "ancillary message: IP_RECVIF: if="+wantIF) ||
				strings.Contains(stderr, "IP_RECVIF: "+wantIF)
			if !hasDst || !hasIF {
				t.Fatalf("missing destination/interface diagnostics: %s", stderr)
			}
		})
	}
	t.Run("env", func(t *testing.T) {
		script := filepath.Join(t.TempDir(), "print-socat-ip.sh")
		body := "#!/bin/sh\nprintf '%s\\n' \"$SOCAT_IP_DSTADDR\" \"$SOCAT_IP_IF\"\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		want := "127.0.0.1\n" + wantIF + "\n"
		stdout, _ := runRawIPReceiver(t, want, "-u",
			"IP4-RECVFROM:253,ip-recvdstaddr,ip-recvif", "EXEC:"+script)
		if stdout != want {
			t.Fatalf("environment output=%q want %q", stdout, want)
		}
	})
}
