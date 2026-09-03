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
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

const (
	matrixPayload = "matrix-ok\n"
	matrixTimeout = 8 * time.Second
)

func TestRelayMatrixTCP4(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name:        "TCP4",
		listenType:  "TCP4-LISTEN",
		connectType: "TCP4",
		startPort:   startTCPTestServer,
	})
}

func TestRelayMatrixTLS(t *testing.T) {
	cert := listenCert(t)
	runStreamFamilyMatrix(t, streamFamily{
		name:        "TLS",
		listenType:  "TLS-LISTEN",
		connectType: "TLS",
		listenExtra: fmt.Sprintf("verify=0,cert=%s", cert),
		connectOpt:  "verify=0",
		startPort:   startTCPTestServer,
	})
}

func TestRelayMatrixWS(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name:        "WS",
		listenType:  "WS-LISTEN",
		connectType: "WS",
		startPort:   startTCPTestServer,
	})
}

func TestRelayMatrixQUIC(t *testing.T) {
	cert := listenCert(t)
	runStreamFamilyMatrix(t, streamFamily{
		name:        "QUIC",
		listenType:  "QUIC-LISTEN",
		connectType: "QUIC",
		listenExtra: fmt.Sprintf("fork,verify=0,cert=%s", cert),
		connectOpt:  "verify=0",
		startPort:   startQUICTestServer,
		clientArgs:  []string{"-t", "2"},
		serverArgs:  []string{"-t", "2"},
		retries:     3,
	})
}

func TestRelayMatrixSCTP4(t *testing.T) {
	bin := socatBin(t)
	probe := exec.Command(bin, os.DevNull, "SCTP4-L:0,accept-timeout=0.05")
	if err := probe.Run(); err != nil {
		t.Skipf("kernel SCTP not usable: %v", err)
	}
	runStreamFamilyMatrix(t, streamFamily{
		name:        "SCTP4",
		listenType:  "SCTP4-LISTEN",
		connectType: "SCTP4",
		startPort:   startSCTPTestServer,
		sctpEcho:    true,
		clientArgs:  []string{"-t", "2"},
		serverArgs:  []string{"-t", "2"},
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
	path := filepath.Join(t.TempDir(), "udp.bin")
	port, srv := startUDPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(socatBin(t), "-t", "2", "-u",
			fmt.Sprintf("UDP4-RECVFROM:%d,reuseaddr,bind=127.0.0.1", port),
			"CREATE:"+path,
		)
	})
	_, errb, err := runSocat(t, []byte(matrixPayload), "-t", "2", "-u", "STDIN",
		fmt.Sprintf("UDP4-SENDTO:127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("UDP send: %v err=%s srv=%s", err, errb, srv.stderr.String())
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
	t.Fatalf("UDP file %q err=%v srv=%s", got, err, srv.stderr.String())
}

func TestRelayMatrixBridgeTCPUNIX(t *testing.T) {
	runTCPBridge(t, unixEchoPeer)
}

func TestRelayMatrixBridgeTCPTLS(t *testing.T) {
	cert := listenCert(t)
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port, proc := startTCPTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(socatBin(t), fmt.Sprintf("TLS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
		})
		return fmt.Sprintf("TLS:127.0.0.1:%d,verify=0", port), func() {
			if t.Failed() {
				t.Log(proc.stderr.String())
			}
		}
	})
}

func TestRelayMatrixBridgeTCPWS(t *testing.T) {
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port, proc := startTCPTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(socatBin(t), fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port), "PIPE")
		})
		return fmt.Sprintf("WS:127.0.0.1:%d", port), func() {
			if t.Failed() {
				t.Log(proc.stderr.String())
			}
		}
	})
}

func TestRelayMatrixBridgeTCPQUIC(t *testing.T) {
	cert := listenCert(t)
	runTCPBridge(t, func(t *testing.T) (connect string, stop func()) {
		port, proc := startQUICTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(socatBin(t), "-t", "2", fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
		})
		return fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port), func() {
			if t.Failed() {
				t.Log(proc.stderr.String())
			}
		}
	})
}

type streamFamily struct {
	name        string
	listenType  string
	connectType string
	listenExtra string
	connectOpt  string
	startPort   func(t *testing.T, command func(int) *exec.Cmd) (int, *testProcess)
	unix        bool
	clientArgs  []string
	serverArgs  []string
	retries     int
	sctpEcho    bool
	skipU       bool
	skipOneWay  bool
}

func (f streamFamily) listenSpec(port int) string {
	spec := fmt.Sprintf("%s:%d,reuseaddr,bind=127.0.0.1", f.listenType, port)
	if f.listenExtra == "" {
		return spec
	}
	return spec + "," + f.listenExtra
}

func (f streamFamily) connectSpec(port int) string {
	spec := fmt.Sprintf("%s:127.0.0.1:%d", f.connectType, port)
	if f.connectOpt == "" {
		return spec
	}
	return spec + "," + f.connectOpt
}

func startFamilyServer(t *testing.T, f streamFamily, extraLeft []string, right string) (connectSpec string, serverErr func() string) {
	t.Helper()
	if f.unix {
		listenSpec, connectSpec := unixListenSpec(t)
		stderr := &bytes.Buffer{}
		args := append(append([]string{}, extraLeft...), listenSpec, right)
		startSocat(t, stderr, args...)
		waitUnixPath(t, listenSpec)
		return connectSpec, stderr.String
	}
	port, proc := f.startPort(t, func(port int) *exec.Cmd {
		args := append(append([]string{}, extraLeft...), f.listenSpec(port), right)
		return exec.Command(socatBin(t), args...)
	})
	return f.connectSpec(port), proc.stderr.String
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
	connectSpec, serverErr := startFamilyServer(t, f, f.serverArgs, "PIPE")

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
	t.Fatalf("bidir %s: %v out=%q err=%s srv=%s", f.name, err, out, errb, serverErr())
}

func matrixOneWayToFile(t *testing.T, f streamFamily) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oneway.bin")
	connectSpec, serverErr := startFamilyServer(t, f, append(append([]string{}, f.serverArgs...), "-u"), "CREATE:"+path)

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
		t.Fatalf("-u %s send: %v err=%s srv=%s", f.name, err, errb, serverErr())
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
	t.Fatalf("-u %s file %q err=%v client=%s srv=%s", f.name, got, err, errb, serverErr())
}

func matrixOneWayFromText(t *testing.T, f streamFamily) {
	t.Helper()
	connectSpec, serverErr := startFamilyServer(t, f, append(append([]string{}, f.serverArgs...), "-U"), "TEXT:"+strings.TrimSuffix(matrixPayload, "\n"))

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
	t.Fatalf("-U %s: %v out=%q err=%s srv=%s", f.name, err, out, errb, serverErr())
}

func unixListenSpec(t *testing.T) (string, string) {
	path := testutil.UnixSocketPath(t, "echo.sock")
	return fmt.Sprintf("UNIX-LISTEN:%s,unlink-early", path), "UNIX-CONNECT:" + path
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
	t.Fatalf("timeout waiting for UNIX %s", path)
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
	path := testutil.UnixSocketPath(t, "echo.sock")
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
	port, proc := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(socatBin(t), fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port), connect)
	})
	out, errb, err := runSocat(t, []byte(matrixPayload), "stdin!!stdout", fmt.Sprintf("TCP4:127.0.0.1:%d", port))
	if err != nil || string(out) != matrixPayload {
		t.Fatalf("bridge: %v out=%q err=%s srv=%s", err, out, errb, proc.stderr.String())
	}
}
