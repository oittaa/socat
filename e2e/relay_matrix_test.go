//go:build e2e && relaymatrix

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	matrixPayload = "matrix-ok\n"
	matrixTimeout = 8 * time.Second
)

func TestRelayMatrixTCP4(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name:   "TCP4",
		listen: tcpListenSpec("TCP4-LISTEN", "TCP4"),
		wait:   waitTCPPort,
	})
}

func TestRelayMatrixUNIX(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name:   "UNIX",
		listen: unixListenSpec,
		wait:   waitUnixPath,
	})
}

func TestRelayMatrixTLS(t *testing.T) {
	cert := listenCert(t)
	runStreamFamilyMatrix(t, streamFamily{
		name:        "TLS",
		listen:      tcpListenSpec("TLS-LISTEN", "TLS"),
		listenExtra: fmt.Sprintf("verify=0,cert=%s", cert),
		connectOpt:  "verify=0",
		wait:        waitTCPPort,
	})
}

func TestRelayMatrixWS(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name:   "WS",
		listen: tcpListenSpec("WS-LISTEN", "WS"),
		wait:   waitTCPPort,
	})
}

func TestRelayMatrixQUIC(t *testing.T) {
	cert := listenCert(t)
	runStreamFamilyMatrix(t, streamFamily{
		name:        "QUIC",
		listen:      udpListenSpec("QUIC-LISTEN", "QUIC"),
		listenExtra: fmt.Sprintf("fork,verify=0,cert=%s", cert),
		connectOpt:  "verify=0",
		wait:        waitUDPPort,
		clientArgs:  []string{"-t", "2"},
		serverArgs:  []string{"-t", "2"},
		retries:     3,
		// bidir matches TestQUICEcho (fork + PIPE). One-way listen+CREATE is
		// racy (client can finish before accept opens the file). -U works
		// because a read-only QUIC client half-closes send after OpenStream.
		skipOneWay: true,
	})
}

func TestRelayMatrixSCTP4(t *testing.T) {
	bin := socatBin(t)
	probe := exec.Command(bin, os.DevNull, "SCTP4-L:0,accept-timeout=0.05")
	if err := probe.Run(); err != nil {
		t.Skipf("kernel SCTP not usable: %v", err)
	}
	runStreamFamilyMatrix(t, streamFamily{
		name:       "SCTP4",
		listen:     tcpListenSpec("SCTP4-LISTEN", "SCTP4"),
		wait:       waitSleep,
		sctpEcho:   true,
		clientArgs: []string{"-t", "2"},
		serverArgs: []string{"-t", "2"},
	})
}

func TestRelayMatrixFILE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	out, errb, err := runSocat(t, []byte(matrixPayload), "-u", "STDIN", "CREATE:"+path)
	if err != nil {
		t.Fatalf("CREATE: %v out=%q err=%s", err, out, errb)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != matrixPayload {
		t.Fatalf("CREATE wrote %q", got)
	}

	readPath := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(readPath, []byte(matrixPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, err = runSocat(t, nil, "-u", "OPEN:"+readPath, "STDOUT")
	if err != nil {
		t.Fatalf("OPEN: %v out=%q err=%s", err, out, errb)
	}
	if string(out) != matrixPayload {
		t.Fatalf("OPEN read %q", out)
	}
}

func TestRelayMatrixUDP4OneWay(t *testing.T) {
	port := freeUDPPort(t)
	path := filepath.Join(t.TempDir(), "udp.bin")
	stderr := &bytes.Buffer{}
	startSocat(t, stderr, "-t", "2", "-u",
		fmt.Sprintf("UDP4-RECVFROM:%d,reuseaddr,bind=127.0.0.1", port),
		"CREATE:"+path,
	)
	waitUDPListen(t, port, 2*time.Second)
	_, errb, err := runSocat(t, []byte(matrixPayload), "-t", "2", "-u", "STDIN",
		fmt.Sprintf("UDP4-SENDTO:127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("UDP send: %v err=%s srv=%s", err, errb, stderr)
	}
	deadline := time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got, err = os.ReadFile(path)
		if err == nil && string(got) == matrixPayload {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("UDP file %q err=%v srv=%s", got, err, stderr)
}

func TestRelayMatrixBridgeTCPUNIX(t *testing.T) {
	runTCPBridge(t, unixEchoPeer)
}

func TestRelayMatrixBridgeTCPTLS(t *testing.T) {
	cert := listenCert(t)
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port := freePort(t)
		stderr := &bytes.Buffer{}
		cmd := startSocat(t, stderr, fmt.Sprintf("TLS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
		waitTCPListen(t, port, tcpListenerStartupTimeout)
		return fmt.Sprintf("TLS:127.0.0.1:%d,verify=0", port), func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			if t.Failed() {
				t.Log(stderr.String())
			}
		}
	})
}

func TestRelayMatrixBridgeTCPWS(t *testing.T) {
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port := freePort(t)
		stderr := &bytes.Buffer{}
		cmd := startSocat(t, stderr, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port), "PIPE")
		waitTCPListen(t, port, tcpListenerStartupTimeout)
		return fmt.Sprintf("WS:127.0.0.1:%d", port), func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			if t.Failed() {
				t.Log(stderr.String())
			}
		}
	})
}

func TestRelayMatrixBridgeTCPQUIC(t *testing.T) {
	cert := listenCert(t)
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port := freeUDPPort(t)
		stderr := &bytes.Buffer{}
		cmd := startSocat(t, stderr, "-t", "2", fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
		waitUDPListen(t, port, 2*time.Second)
		return fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port), func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			if t.Failed() {
				t.Log(stderr.String())
			}
		}
	})
}

type streamFamily struct {
	name        string
	listen      func(t *testing.T) (listenSpec, connectSpec string)
	listenExtra string
	connectOpt  string
	wait        func(t *testing.T, listenSpec string)
	clientArgs  []string
	serverArgs  []string
	retries     int
	sctpEcho    bool
	skipU       bool
	skipOneWay  bool
}

func (f streamFamily) withListenOpts(spec string) string {
	if f.listenExtra == "" {
		return spec
	}
	if strings.Contains(spec, ",") {
		return spec + "," + f.listenExtra
	}
	return spec + "," + f.listenExtra
}

func (f streamFamily) withConnectOpts(spec string) string {
	if f.connectOpt == "" {
		return spec
	}
	return spec + "," + f.connectOpt
}

func runStreamFamilyMatrix(t *testing.T, f streamFamily) {
	t.Helper()
	t.Run("bidir", func(t *testing.T) { matrixBidir(t, f) })
	t.Run("u", func(t *testing.T) {
		if f.skipOneWay {
			t.Skip("one-way listen+CREATE is not reliable for this family")
		}
		matrixOneWayToFile(t, f)
	})
	t.Run("U", func(t *testing.T) {
		if f.skipU {
			t.Skip("this family needs a client write to open the stream")
		}
		matrixOneWayFromText(t, f)
	})
}

func matrixBidir(t *testing.T, f streamFamily) {
	t.Helper()
	listenSpec, connectSpec := f.listen(t)
	listenSpec = f.withListenOpts(listenSpec)
	connectSpec = f.withConnectOpts(connectSpec)
	stderr := &bytes.Buffer{}
	args := append(append([]string{}, f.serverArgs...), listenSpec, "PIPE")
	startSocat(t, stderr, args...)
	f.wait(t, listenSpec)

	payload := []byte(matrixPayload)
	clientBase := append([]string{}, f.clientArgs...)
	var out, errb []byte
	var err error
	tries := f.retries
	if tries < 1 {
		tries = 1
	}
	for attempt := 0; attempt < tries; attempt++ {
		if f.sctpEcho {
			out, errb, err = runSCTPEchoClient(t, payload, append(append([]string{}, clientBase...), "-", connectSpec)...)
		} else {
			out, errb, err = runSocat(t, payload, append(append([]string{}, clientBase...), "stdin!!stdout", connectSpec)...)
		}
		if err == nil && bytes.Contains(out, bytes.TrimSpace(payload)) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("bidir %s: %v out=%q err=%s srv=%s", f.name, err, out, errb, stderr)
}

func matrixOneWayToFile(t *testing.T, f streamFamily) {
	t.Helper()
	listenSpec, connectSpec := f.listen(t)
	listenSpec = f.withListenOpts(listenSpec)
	connectSpec = f.withConnectOpts(connectSpec)
	path := filepath.Join(t.TempDir(), "oneway.bin")
	stderr := &bytes.Buffer{}
	args := append(append([]string{}, f.serverArgs...), "-u", listenSpec, "CREATE:"+path)
	startSocat(t, stderr, args...)
	f.wait(t, listenSpec)

	payload := []byte(matrixPayload)
	tries := f.retries
	if tries < 1 {
		tries = 1
	}
	var errb []byte
	var err error
	for attempt := 0; attempt < tries; attempt++ {
		_, errb, err = runSocat(t, payload, append(append([]string{}, f.clientArgs...), "-u", "STDIN", connectSpec)...)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("-u %s send: %v err=%s srv=%s", f.name, err, errb, stderr)
	}
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got, err = os.ReadFile(path)
		if err == nil && string(got) == matrixPayload {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("-u %s file %q err=%v client=%s srv=%s", f.name, got, err, errb, stderr)
}

func matrixOneWayFromText(t *testing.T, f streamFamily) {
	t.Helper()
	listenSpec, connectSpec := f.listen(t)
	listenSpec = f.withListenOpts(listenSpec)
	connectSpec = f.withConnectOpts(connectSpec)
	stderr := &bytes.Buffer{}
	args := append(append([]string{}, f.serverArgs...), "-U", listenSpec, "TEXT:"+strings.TrimSuffix(matrixPayload, "\n"))
	startSocat(t, stderr, args...)
	f.wait(t, listenSpec)

	tries := f.retries
	if tries < 1 {
		tries = 1
	}
	var out, errb []byte
	var err error
	for attempt := 0; attempt < tries; attempt++ {
		out, errb, err = runSocat(t, nil, append(append([]string{}, f.clientArgs...), "-u", connectSpec, "STDOUT")...)
		if err == nil && strings.Contains(string(out), strings.TrimSpace(matrixPayload)) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("-U %s: %v out=%q err=%s srv=%s", f.name, err, out, errb, stderr)
}

func tcpListenSpec(listenType, connectType string) func(t *testing.T) (string, string) {
	return func(t *testing.T) (string, string) {
		port := freePort(t)
		return fmt.Sprintf("%s:%d,reuseaddr,bind=127.0.0.1", listenType, port),
			fmt.Sprintf("%s:127.0.0.1:%d", connectType, port)
	}
}

func udpListenSpec(listenType, connectType string) func(t *testing.T) (string, string) {
	return func(t *testing.T) (string, string) {
		port := freeUDPPort(t)
		return fmt.Sprintf("%s:%d,reuseaddr,bind=127.0.0.1", listenType, port),
			fmt.Sprintf("%s:127.0.0.1:%d", connectType, port)
	}
}

func unixListenSpec(t *testing.T) (string, string) {
	path := filepath.Join(t.TempDir(), "echo.sock")
	return fmt.Sprintf("UNIX-LISTEN:%s,unlink-early", path), "UNIX-CONNECT:" + path
}

func waitTCPPort(t *testing.T, listenSpec string) {
	t.Helper()
	port, ok := portFromListenSpec(listenSpec)
	if !ok {
		t.Fatalf("no port in %q", listenSpec)
	}
	waitTCPListen(t, port, tcpListenerStartupTimeout)
}

func waitUDPPort(t *testing.T, listenSpec string) {
	t.Helper()
	port, ok := portFromListenSpec(listenSpec)
	if !ok {
		t.Fatalf("no port in %q", listenSpec)
	}
	waitUDPListen(t, port, 2*time.Second)
	// QUIC accept is not visible as a TCP bind. Give the server a short
	// extra window after the UDP port probe.
	time.Sleep(250 * time.Millisecond)
}

func waitUnixPath(t *testing.T, listenSpec string) {
	t.Helper()
	_, path, ok := strings.Cut(listenSpec, ":")
	if !ok {
		t.Fatalf("no path in %q", listenSpec)
	}
	path, _, _ = strings.Cut(path, ",")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if runtime.GOOS == "windows" {
		t.Skipf("UNIX listen path %q did not appear", path)
	}
	t.Fatalf("timeout waiting for UNIX %s", path)
}

func waitSleep(t *testing.T, _ string) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
}

func portFromListenSpec(spec string) (int, bool) {
	_, rest, ok := strings.Cut(spec, ":")
	if !ok {
		return 0, false
	}
	num, _, _ := strings.Cut(rest, ",")
	var port int
	if _, err := fmt.Sscanf(num, "%d", &port); err != nil || port <= 0 {
		return 0, false
	}
	return port, true
}

func startSocat(t *testing.T, stderr *bytes.Buffer, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(socatBin(t), args...)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

func runSocat(t *testing.T, stdin []byte, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), matrixTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, socatBin(t), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func runSCTPEchoClient(t *testing.T, payload []byte, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), matrixTimeout)
	defer cancel()
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(payload)
		time.Sleep(400 * time.Millisecond)
		_ = pw.Close()
	}()
	cmd := exec.CommandContext(ctx, socatBin(t), args...)
	cmd.Stdin = pr
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func unixEchoPeer(t *testing.T) (connect string, stop func()) {
	path := filepath.Join(t.TempDir(), "echo.sock")
	stderr := &bytes.Buffer{}
	cmd := startSocat(t, stderr, fmt.Sprintf("UNIX-LISTEN:%s,unlink-early,fork", path), "PIPE")
	waitUnixPath(t, "UNIX-LISTEN:"+path)
	return "UNIX-CONNECT:" + path, func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Log(stderr.String())
		}
	}
}

func runTCPBridge(t *testing.T, peer func(t *testing.T) (connect string, stop func())) {
	t.Helper()
	connect, stop := peer(t)
	defer stop()
	port := freePort(t)
	stderr := &bytes.Buffer{}
	startSocat(t, stderr, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port), connect)
	waitTCPListen(t, port, tcpListenerStartupTimeout)
	out, errb, err := runSocat(t, []byte(matrixPayload), "stdin!!stdout", fmt.Sprintf("TCP4:127.0.0.1:%d", port))
	if err != nil || string(out) != matrixPayload {
		t.Fatalf("bridge: %v out=%q err=%s srv=%s", err, out, errb, stderr)
	}
}
