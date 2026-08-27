//go:build e2e && unix

package e2e_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionHasTERMIOS(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_TERMIOS 1")) {
		t.Fatalf("missing WITH_TERMIOS 1:\n%s", out)
	}
	hh := capabilityOutput(t, "-hh")
	for _, opt := range []string{"pty-wait-slave", "tiocswinsz", "ctty", "cfmakeraw", "sane"} {
		if !bytes.Contains(hh, []byte(" "+opt+" ")) {
			t.Fatalf("help missing %s:\n%s", opt, hh)
		}
	}
	hhh := capabilityOutput(t, "-hhh")
	for _, opt := range []string{"vintr", "intr", "pendin"} {
		if !bytes.Contains(hhh, []byte(" "+opt+" ")) {
			t.Fatalf("-hhh missing %s:\n%s", opt, hhh)
		}
	}
}

func TestSystemChdirUsesChildDirectory(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	out, err := exec.Command(bin, "-u", "SYSTEM:pwd,chdir="+dir, "STDOUT").CombinedOutput()
	if err != nil {
		t.Fatalf("socat: %v: %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat pwd output %q: %v", got, err)
	}
	wantInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat temp directory %q: %v", dir, err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatalf("pwd=%q does not identify chdir directory %q", got, dir)
	}
}

// TestTCPConnectMaxChildren — classic TCP_CONNECT_MAXCHILDREN shape:
// CONNECT,fork,max-children=2 with a slow EXEC producer and a forking listener.
func TestTCPConnectMaxChildren(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	qdir := filepath.Join(dir, "q")
	if err := os.Mkdir(qdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Three queue items; max-children=2 means the third waits for a free slot.
	for i, name := range []string{"01", "02", "03"} {
		line := fmt.Sprintf("msg%d\n", i+1)
		if err := os.WriteFile(filepath.Join(qdir, name), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// queue worker: print first file, hold 200ms so concurrency is visible.
	worker := filepath.Join(dir, "queue.sh")
	script := `#!/bin/bash
d="$1"
t="$2"
shopt -s nullglob
f="$(ls "$d" | head -1)"
if test -n "$f" && mkdir "$d/.$f.d" 2>/dev/null && test -f "$d/$f"; then
  cat "$d/$f"
  rm -f "$d/$f"
  rmdir "$d/.$f.d" 2>/dev/null
  sleep "$t"
  exit 0
fi
exit 1
`
	if err := os.WriteFile(worker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	// Reader: append accepted data to out.
	srv := exec.Command(bin, "-U",
		"CREATE:"+out+",append",
		fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
	)
	var srvErr bytes.Buffer
	srv.Stderr = &srvErr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	waitTCPListen(t, port, tcpListenerStartupTimeout)

	// Client: CONNECT fork max-children=2, short interval; EXEC drains queue.
	cli := exec.Command(bin, "-4",
		fmt.Sprintf("TCP4-CONNECT:127.0.0.1:%d,fork,max-children=2,interval=0.05", port),
		fmt.Sprintf("EXEC:%s %s 0.2!!-", worker, qdir),
	)
	var cliErr bytes.Buffer
	cli.Stderr = &cliErr
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cli.Process.Kill()
		_, _ = cli.Process.Wait()
	}()

	// Wait until all three messages arrive (or timeout).
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(out)
		if bytes.Count(b, []byte("msg")) >= 3 {
			got = b
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if bytes.Count(got, []byte("msg")) < 3 {
		t.Fatalf("expected 3 messages, got %q cli=%s srv=%s", got, cliErr.String(), srvErr.String())
	}
	if !bytes.Contains(got, []byte("msg1")) || !bytes.Contains(got, []byte("msg2")) || !bytes.Contains(got, []byte("msg3")) {
		t.Fatalf("missing messages: %q", got)
	}
}
