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
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_WEBSOCKET 1")) {
		t.Fatalf("missing WITH_WEBSOCKET in -V:\n%s", out)
	}
}

func TestWSHelpTypes(t *testing.T) {
	out := capabilityOutput(t, "-h")
	for _, name := range []string{"WS", "WS-CONNECT", "WSS", "WSS-CONNECT", "WS-LISTEN", "WSS-LISTEN"} {
		if !bytes.Contains(out, []byte(name)) {
			t.Fatalf("-h missing %s:\n%s", name, out)
		}
	}
	hh := capabilityOutput(t, "-hh")
	for _, opt := range []string{"path", "origin", "protocol"} {
		if !bytes.Contains(hh, []byte(" "+opt+" ")) {
			t.Fatalf("-hh missing option %s:\n%s", opt, hh)
		}
	}
}

// TestWSEcho — WS-LISTEN + PIPE echo; client uses stdin!!stdout.
func TestWSEcho(t *testing.T) {
	bin := socatBin(t)
	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	})

	payload := fmt.Sprintf("ws-echo %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d", port))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
	}
}

// TestWSSEcho — WSS-LISTEN with a throwaway cert; client verify=0.
func TestWSSEcho(t *testing.T) {
	bin := socatBin(t)
	cert := listenCert(t)
	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("WSS-LISTEN:%d,reuseaddr,bind=127.0.0.1,verify=0,cert=%s", port, cert), "PIPE")
	})

	payload := fmt.Sprintf("wss-echo %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WSS:127.0.0.1:%d,verify=0", port))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
	}
}

// TestWSPath — path in the address and path= option; wrong path fails.
func TestWSPath(t *testing.T) {
	bin := socatBin(t)
	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d/echo,reuseaddr,bind=127.0.0.1,fork", port), "PIPE")
	})

	bad := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d/other", port))
	bad.Stdin = bytes.NewBufferString("nope")
	if out, err := bad.CombinedOutput(); err == nil {
		t.Fatalf("expected path mismatch, got %q srv=%s", out, srv.stderr.String())
	}

	payload := "path-ok\n"
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("WS:127.0.0.1:%d,path=/echo", port))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
	}
}

// TestTCPToWSBridge — raw TCP client through TCP-LISTEN → WS client → WS-LISTEN echo.
func TestTCPToWSBridge(t *testing.T) {
	bin := socatBin(t)
	wsPort, echo := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port), "PIPE")
	})
	tcpPort, bridge := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin,
			fmt.Sprintf("TCP-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			fmt.Sprintf("WS:127.0.0.1:%d", wsPort),
		)
	})

	payload := fmt.Sprintf("tcp-ws %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("TCP:127.0.0.1:%d", tcpPort))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s bridge=%s echo=%s", err, cliErr.String(), bridge.stderr.String(), echo.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q bridge=%s echo=%s", out, payload, bridge.stderr.String(), echo.stderr.String())
	}
}

// TestWSOriginReject — server origin= rejects a non-matching Origin header.
func TestWSOriginReject(t *testing.T) {
	bin := socatBin(t)
	port, _ := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,origin=example.com", port), "PIPE")
	})

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
