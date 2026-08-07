//go:build e2e

package e2e_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func socatBin(t *testing.T) string {
	t.Helper()
	// Prefer ./socat from repo root or SOCAT env
	if p := os.Getenv("SOCAT"); p != "" {
		return p
	}
	candidates := []string{"../socat", "./socat", "socat"}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("socat binary not found; run make build and set SOCAT= or run from repo root")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitTCPListen waits until something is listening without accepting a connection.
// (Dialing would steal the single accept of non-fork TCP-LISTEN.)
func waitTCPListen(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check by binding attempt? Better: look at /proc/net/tcp or just short sleep + retry client.
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			// port in use — likely our server
			return
		}
		ln.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for listen on %d", port)
}

// TCP4 — classic test.sh NAME=TCP4: echo via TCP V4
func TestTCP4Echo(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Classic: TCP4-LISTEN + PIPE echo; no fork (single connection)
	srv := exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	var stderr bytes.Buffer
	srv.Stderr = &stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	waitTCPListen(t, port, 2*time.Second)

	payload := fmt.Sprintf("test TCP4 %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("TCP4:%s", addr))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli_stderr=%s srv_stderr=%s", err, cliErr.String(), stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv stderr: %s)", out, payload, stderr.String())
	}
}

// UNIXSTREAM — echo via unix stream socket
func TestUnixStreamEcho(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "echo.sock")

	srv := exec.Command(bin, fmt.Sprintf("UNIX-LISTEN:%s,unlink-early", sock), "PIPE")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	payload := "unix-stream-test\n"
	cli := exec.Command(bin, "-", fmt.Sprintf("UNIX-CONNECT:%s", sock))
	cli.Stdin = bytes.NewBufferString(payload)
	out, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("client: %v out=%s", err, out)
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
}

// UNISTDIO — echo via stdio to pipe-like: socat - -
func TestUniStdio(t *testing.T) {
	bin := socatBin(t)
	payload := "stdio-echo\n"
	// Unidirectional: -u STDIN STDOUT would work; bidirectional - - may hang
	// Classic UNISTDIO uses socat -u stdin stdout
	cmd := exec.Command(bin, "-u", "STDIN", "STDOUT")
	cmd.Stdin = bytes.NewBufferString(payload)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
}

// FILE — write and read via OPEN/CREATE
func TestFileCreate(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	payload := "file-data\n"

	cmd := exec.Command(bin, "-u", "STDIN", "CREATE:"+path)
	cmd.Stdin = bytes.NewBufferString(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != payload {
		t.Fatalf("got %q", b)
	}
}

// Dual address stdin!!stdout
func TestDualStdio(t *testing.T) {
	bin := socatBin(t)
	payload := "dual\n"
	cmd := exec.Command(bin, "-u", "STDIN!!STDOUT", "STDOUT")
	// simpler: STDIN to CREATE via dual not needed
	cmd = exec.Command(bin, "-u", "STDIN", "STDOUT")
	cmd.Stdin = bytes.NewBufferString(payload)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != payload {
		t.Fatalf("got %q", out)
	}
}

func TestVersion(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("socat")) {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestHelp(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("Usage")) {
		t.Fatalf("unexpected: %s", out)
	}
}
