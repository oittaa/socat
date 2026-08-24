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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var capabilityCache = struct {
	sync.Mutex
	output map[string][]byte
}{output: make(map[string][]byte)}

const (
	tcpListenerStartupTimeout = 10 * time.Second
	tcpListenerStartAttempts  = 3
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type testProcess struct {
	cmd     *exec.Cmd
	stderr  lockedBuffer
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
}

func startTestProcess(cmd *exec.Cmd) (*testProcess, error) {
	p := &testProcess{cmd: cmd, done: make(chan struct{})}
	cmd.Stderr = &p.stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := cmd.Wait()
		p.waitMu.Lock()
		p.waitErr = err
		p.waitMu.Unlock()
		close(p.done)
	}()
	return p, nil
}

func (p *testProcess) status() (error, bool) {
	select {
	case <-p.done:
		p.waitMu.Lock()
		defer p.waitMu.Unlock()
		return p.waitErr, true
	default:
		return nil, false
	}
}

func (p *testProcess) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Kill()
	<-p.done
}

func waitTCPTestProcess(p *testProcess, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, exited := p.status(); exited {
			return fmt.Errorf("server exited before listening: %v", err)
		}
		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			// Give a child that just lost the bind race time to report its exit.
			select {
			case <-p.done:
				exitErr, _ := p.status()
				return fmt.Errorf("server exited before listening: %v", exitErr)
			case <-time.After(20 * time.Millisecond):
			}
			return nil
		}
		_ = ln.Close()
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for listen on %d", port)
}

// startTCPTestServer tolerates slow CI runners and the unavoidable race between
// reserving a free port and binding it in a child process. Early child exits
// retain stderr so a real startup failure is actionable instead of timing out.
func startTCPTestServer(t *testing.T, command func(port int) *exec.Cmd) (int, *testProcess) {
	t.Helper()
	var failures []string
	for attempt := 1; attempt <= tcpListenerStartAttempts; attempt++ {
		port := freePort(t)
		process, err := startTestProcess(command(port))
		if err != nil {
			t.Fatalf("start TCP test server: %v", err)
		}
		err = waitTCPTestProcess(process, port, tcpListenerStartupTimeout)
		if err == nil {
			t.Cleanup(process.stop)
			return port, process
		}
		process.stop()
		failure := fmt.Sprintf("attempt %d port %d: %v; stderr=%s", attempt, port, err, process.stderr.String())
		failures = append(failures, failure)
		if attempt < tcpListenerStartAttempts {
			t.Logf("TCP test server startup failed, retrying: %s", failure)
		}
	}
	t.Fatalf("TCP test server failed after %d attempts: %s", tcpListenerStartAttempts, strings.Join(failures, "; "))
	return 0, nil
}

func skipUnlessLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
}

// capabilityOutput caches immutable command metadata. Capability tests used to
// launch the same binary more than twenty times for -V/-h/-hh/-hhh.
func capabilityOutput(t *testing.T, flag string) []byte {
	t.Helper()
	bin := socatBin(t)
	key := bin + "\x00" + flag
	capabilityCache.Lock()
	defer capabilityCache.Unlock()
	if out, ok := capabilityCache.output[key]; ok {
		return out
	}
	out, err := exec.Command(bin, flag).CombinedOutput()
	if err != nil {
		t.Fatalf("socat %s: %v: %s", flag, err, out)
	}
	capabilityCache.output[key] = out
	return out
}

func TestRejectsInvalidAddressOptionsBeforeSideEffects(t *testing.T) {
	bin := socatBin(t)
	tests := []struct {
		name   string
		option string
		want   string
	}{
		{name: "unknown", option: "totally-unknown=1", want: "unknown option"},
		{name: "invalid-perm", option: "perm=xyz", want: "invalid perm"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "must-not-exist")
			out, err := exec.Command(bin, "-u", "TEXT:data", "CREATE:"+path+","+tc.option).CombinedOutput()
			if err == nil {
				t.Fatalf("command succeeded: %s", out)
			}
			if !bytes.Contains(out, []byte(tc.want)) {
				t.Fatalf("output %q does not contain %q", out, tc.want)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("address validation created %q: %v", path, statErr)
			}
		})
	}
}

func TestChdirCreatesRelativeAddressInRequestedDirectory(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "result.txt")
	out, err := exec.Command(bin, "-u", "TEXT:data", "CREATE:result.txt,chdir="+dir).CombinedOutput()
	if err != nil {
		t.Fatalf("socat: %v: %s", err, out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("contents=%q want data", got)
	}
}

func TestTLSHandshakeTimeoutClosesSilentPeer(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)
	cert := listenCert(t)
	cmd := exec.Command(bin,
		fmt.Sprintf("TLS-LISTEN:%d,bind=127.0.0.1,reuseaddr,fork,verify=0,cert=%s,handshake-timeout=0.1", port, cert),
		"PIPE",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	waitTCPListen(t, port, tcpListenerStartupTimeout)

	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err = conn.Read(b[:])
	if err == nil {
		t.Fatal("silent TLS peer remained open")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("TLS handshake timeout did not close the peer: %s", stderr.String())
	}
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

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	return pc.LocalAddr().(*net.UDPAddr).Port
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
	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Classic: TCP4-LISTEN + PIPE echo; no fork (single connection)
	payload := fmt.Sprintf("test TCP4 %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("TCP4:%s", addr))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli_stderr=%s srv_stderr=%s", err, cliErr.String(), srv.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv stderr: %s)", out, payload, srv.stderr.String())
	}
}

func TestTCPTestServerRetriesEarlyExit(t *testing.T) {
	bin := socatBin(t)
	attempts := 0
	port, _ := startTCPTestServer(t, func(port int) *exec.Cmd {
		attempts++
		if attempts == 1 {
			return exec.Command(bin, "NOT-A-REAL-ADDRESS", "PIPE")
		}
		return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	})
	if attempts != 2 {
		t.Fatalf("startup attempts=%d want 2", attempts)
	}
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
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

// Dual address stdin!!stdout. The !! form must be the command that actually
// runs: an earlier version built this argv and then overwrote it with STDIN.
func TestDualStdio(t *testing.T) {
	bin := socatBin(t)
	payload := "dual\n"
	cmd := exec.Command(bin, "-u", "STDIN!!STDOUT", "STDOUT")
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

func TestVersionHasPOSIXMQ(t *testing.T) {
	skipUnlessLinux(t)
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
	skipUnlessLinux(t)
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
	skipUnlessLinux(t)
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
	skipUnlessLinux(t)
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_SCTP 1")) {
		t.Fatalf("missing WITH_SCTP 1:\n%s", out)
	}
	h := capabilityOutput(t, "-h")
	if !bytes.Contains(h, []byte("SCTP4-")) {
		t.Fatalf("help missing SCTP4-: %s", h)
	}
}

func TestVersion(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("socat")) {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestHelp(t *testing.T) {
	out := capabilityOutput(t, "-h")
	if !bytes.Contains(out, []byte("Usage")) {
		t.Fatalf("unexpected: %s", out)
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

func TestTLSRejectsOpenSSLMethod(t *testing.T) {
	bin := socatBin(t)
	for _, optionName := range []string{"openssl-method", "opensslmethod"} {
		out, err := exec.Command(bin,
			"OPENSSL-LISTEN:0,verify=0,"+optionName+"=DTLS1",
			"PIPE",
		).CombinedOutput()
		if err == nil {
			t.Fatalf("%s: expected unsupported method error, got %q", optionName, out)
		}
		if !bytes.Contains(out, []byte(optionName)) || !bytes.Contains(out, []byte("not supported")) {
			t.Fatalf("%s: unexpected error: %s", optionName, out)
		}
	}

	hhh := capabilityOutput(t, "-hhh")
	if bytes.Contains(hhh, []byte("openssl-method")) {
		t.Fatalf("-hhh advertises unsupported openssl-method:\n%s", hhh)
	}
}

func TestHelpListsTLSAndOpenSSLAlias(t *testing.T) {
	out := capabilityOutput(t, "-h")
	for _, name := range []string{"TLS-LISTEN", "OPENSSL-LISTEN", "SSL-LISTEN"} {
		if !bytes.Contains(out, []byte(name)) {
			t.Fatalf("-h missing %s:\n%s", name, out)
		}
	}
	v := capabilityOutput(t, "-V")
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
	waitTCPListen(t, port, tcpListenerStartupTimeout)

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
