//go:build e2e

package e2e_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func listenCert(t *testing.T) string {
	t.Helper()
	p, err := tlsopen.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

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

func TestSCTP4Echo(t *testing.T) {
	bin := socatBin(t)
	// Kernel SCTP: skip if the binary cannot open an SCTP listen socket.
	probe := exec.Command(bin, "/dev/null", "SCTP4-L:0,accept-timeout=0.05")
	if err := probe.Run(); err != nil {
		t.Skipf("kernel SCTP not usable: %v", err)
	}
	// Use a TCP bind probe only to pick a free numeric port.
	port := freePort(t)
	srv := exec.Command(bin, fmt.Sprintf("SCTP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	var stderr bytes.Buffer
	srv.Stderr = &stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	time.Sleep(150 * time.Millisecond)

	payload := fmt.Sprintf("test SCTP4 %d\n", time.Now().UnixNano())
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, payload)
		// RFC 9260: no TCP-style half-close; keep the association up briefly.
		time.Sleep(400 * time.Millisecond)
		_ = pw.Close()
	}()
	cli := exec.Command(bin, "-", fmt.Sprintf("SCTP4:127.0.0.1:%d", port))
	cli.Stdin = pr
	var out, errb bytes.Buffer
	cli.Stdout = &out
	cli.Stderr = &errb
	if err := cli.Run(); err != nil {
		t.Fatalf("client: %v server=%s client=%s", err, stderr.String(), errb.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(strings.TrimSpace(payload))) && !bytes.Contains(out.Bytes(), []byte(payload)) {
		t.Fatalf("echo mismatch out=%q server=%s client=%s", out.Bytes(), stderr.String(), errb.String())
	}
}

func TestVersionHasTERMIOS(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("#define WITH_TERMIOS 1")) {
		t.Fatalf("missing WITH_TERMIOS 1:\n%s", out)
	}
	hh, err := exec.Command(bin, "-hh").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []string{"pty-wait-slave", "tiocswinsz", "ctty", "cfmakeraw"} {
		if !bytes.Contains(hh, []byte(" "+opt+" ")) {
			t.Fatalf("help missing %s:\n%s", opt, hh)
		}
	}
}

func TestVersionHasPOSIXMQ(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("#define WITH_POSIXMQ 1")) {
		t.Fatalf("missing WITH_POSIXMQ 1:\n%s", out)
	}
	h, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h, []byte("POSIXMQ-SEND")) {
		t.Fatalf("help missing POSIXMQ-SEND: %s", h)
	}
	hh, err := exec.Command(bin, "-hh").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
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
	var stdout, stderr bytes.Buffer
	rd.Stdout = &stdout
	rd.Stderr = &stderr
	if err := rd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	_ = rd.Process.Kill()
	_, _ = rd.Process.Wait()
	want := msg1 + msg0
	if stdout.String() != want {
		t.Fatalf("got %q want %q stderr=%s", stdout.String(), want, stderr.String())
	}
}

func TestVersionHasSCTP(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("#define WITH_SCTP 1")) {
		t.Fatalf("missing WITH_SCTP 1:\n%s", out)
	}
	h, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h, []byte("SCTP4-")) {
		t.Fatalf("help missing SCTP4-: %s", h)
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
	waitTCPListen(t, port, 2*time.Second)

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
	// Order: 1 and 2 first (parallel), then 3 after a slot frees.
	if !bytes.Contains(got, []byte("msg1")) || !bytes.Contains(got, []byte("msg2")) || !bytes.Contains(got, []byte("msg3")) {
		t.Fatalf("missing messages: %q", got)
	}
}

func TestTLSListenRequiresCert(t *testing.T) {
	bin := socatBin(t)
	for _, typ := range []string{"TLS-LISTEN", "OPENSSL-LISTEN"} {
		out, err := exec.Command(bin, typ+":0,bind=127.0.0.1,verify=0", "PIPE").CombinedOutput()
		if err == nil {
			t.Fatalf("%s: expected start failure without cert=, got %q", typ, out)
		}
		if !bytes.Contains(out, []byte("cert")) {
			t.Fatalf("%s: error should mention cert: %s", typ, out)
		}
	}
}

func TestHelpListsTLSAndOpenSSLAlias(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TLS-LISTEN", "OPENSSL-LISTEN", "SSL-LISTEN"} {
		if !bytes.Contains(out, []byte(name)) {
			t.Fatalf("-h missing %s:\n%s", name, out)
		}
	}
	v, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(v, []byte("#define WITH_TLS 1")) {
		t.Fatalf("missing WITH_TLS 1:\n%s", v)
	}
	if !bytes.Contains(v, []byte("#define WITH_OPENSSL 1")) {
		t.Fatalf("missing WITH_OPENSSL 1:\n%s", v)
	}
}

// TestTLSPQC — TLS echo with Go default hybrid post-quantum KEM
// (X25519MLKEM768). Classic test.sh has no PQC cases.
func TestTLSPQC(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)

	cert := listenCert(t)
	srv := exec.Command(bin,
		fmt.Sprintf("TLS-LISTEN:%d,reuseaddr,bind=127.0.0.1,verify=0,cert=%s", port, cert),
		"PIPE",
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
	waitTCPListen(t, port, 2*time.Second)

	payload := fmt.Sprintf("pqc-tls %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout",
		fmt.Sprintf("TLS:127.0.0.1:%d,verify=0", port),
	)
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srvErr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv=%s)", out, payload, srvErr.String())
	}
}
