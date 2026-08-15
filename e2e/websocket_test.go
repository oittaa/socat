//go:build e2e

package e2e_test

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestWSVersionFeature: -V advertises WITH_WEBSOCKET (Go extra, not classic).
func TestWSVersionFeature(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("#define WITH_WEBSOCKET 1")) {
		t.Fatalf("missing WITH_WEBSOCKET in -V:\n%s", out)
	}
}

func TestWSHelpTypes(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"WS", "WS-CONNECT", "WSS", "WSS-CONNECT", "WS-LISTEN", "WSS-LISTEN"} {
		if !bytes.Contains(out, []byte(name)) {
			t.Fatalf("-h missing %s:\n%s", name, out)
		}
	}
	hh, err := exec.Command(bin, "-hh").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []string{"path", "origin", "protocol"} {
		if !bytes.Contains(hh, []byte(" "+opt+" ")) {
			t.Fatalf("-hh missing option %s:\n%s", opt, hh)
		}
	}
}

// TestWSEcho — WS-LISTEN + PIPE echo; client uses stdin!!stdout.
func TestWSEcho(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)

	srv := exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
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

	payload := fmt.Sprintf("ws-echo %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d", port))
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

// TestWSSEcho — WSS-LISTEN with a throwaway cert; client verify=0.
func TestWSSEcho(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)
	cert := listenCert(t)

	srv := exec.Command(bin, fmt.Sprintf("WSS-LISTEN:%d,reuseaddr,bind=127.0.0.1,verify=0,cert=%s", port, cert), "PIPE")
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

	payload := fmt.Sprintf("wss-echo %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WSS:127.0.0.1:%d,verify=0", port))
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

// TestWSPath — path in the address and path= option; wrong path fails.
func TestWSPath(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)

	srv := exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d/echo,reuseaddr,bind=127.0.0.1,fork", port), "PIPE")
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

	bad := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d/other", port))
	bad.Stdin = bytes.NewBufferString("nope")
	if out, err := bad.CombinedOutput(); err == nil {
		t.Fatalf("expected path mismatch, got %q srv=%s", out, srvErr.String())
	}

	payload := "path-ok\n"
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d,path=/echo", port))
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

// TestTCPToWSBridge — raw TCP client through TCP-LISTEN → WS client → WS-LISTEN echo.
func TestTCPToWSBridge(t *testing.T) {
	bin := socatBin(t)
	wsPort := freePort(t)
	tcpPort := freePort(t)

	echo := exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", wsPort), "PIPE")
	var echoErr bytes.Buffer
	echo.Stderr = &echoErr
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = echo.Process.Kill()
		_, _ = echo.Process.Wait()
	}()
	waitTCPListen(t, wsPort, 2*time.Second)

	bridge := exec.Command(bin,
		fmt.Sprintf("TCP-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", tcpPort),
		fmt.Sprintf("WS:127.0.0.1:%d", wsPort),
	)
	var bridgeErr bytes.Buffer
	bridge.Stderr = &bridgeErr
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = bridge.Process.Kill()
		_, _ = bridge.Process.Wait()
	}()
	waitTCPListen(t, tcpPort, 2*time.Second)

	payload := fmt.Sprintf("tcp-ws %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("TCP:127.0.0.1:%d", tcpPort))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s bridge=%s echo=%s", err, cliErr.String(), bridgeErr.String(), echoErr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q bridge=%s echo=%s", out, payload, bridgeErr.String(), echoErr.String())
	}
}

// TestWSOriginReject — server origin= rejects a non-matching Origin header.
func TestWSOriginReject(t *testing.T) {
	bin := socatBin(t)
	port := freePort(t)

	srv := exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,origin=example.com", port), "PIPE")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	waitTCPListen(t, port, 2*time.Second)

	bad := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d,origin=http://evil.com", port))
	bad.Stdin = bytes.NewBufferString("x")
	out, err := bad.CombinedOutput()
	if err == nil {
		t.Fatalf("expected origin rejection, got %q", out)
	}
	if !strings.Contains(strings.ToLower(string(out)+err.Error()), "origin") &&
		!strings.Contains(strings.ToLower(string(out)), "403") &&
		!strings.Contains(strings.ToLower(string(out)), "failed") {
		// Dial error text from coder/websocket is enough; non-zero exit is the contract.
		t.Logf("origin reject output: %s", out)
	}

	payload := "origin-ok\n"
	ok := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d,origin=http://example.com", port))
	var okErr bytes.Buffer
	ok.Stdin = bytes.NewBufferString(payload)
	ok.Stderr = &okErr
	got, err := ok.Output()
	if err != nil {
		t.Fatalf("matching origin: %v %s", err, okErr.String())
	}
	if string(got) != payload {
		t.Fatalf("got %q want %q", got, payload)
	}
}
