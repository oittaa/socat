//go:build e2e && linux

package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func recverrOutputHasDiagnostic(text string) bool {
	return strings.Contains(text, "IP_RECVERR") || strings.Contains(text, "received ICMP")
}

func runRecvErrClosedPort(t *testing.T, addressFmt string) (string, error) {
	t.Helper()
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, socatBin(t), "-d", "-d", "-d", "-t", "1",
		"STDIO",
		fmt.Sprintf(addressFmt, port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	if _, err := io.WriteString(stdin, "hi\n"); err != nil {
		t.Fatal(err)
	}
	// Keep stdin open across CombinedOutput so EOF cannot beat a connection
	// refused error. CommandContext bounds the wait; Wait closes the pipe
	// after the process exits.
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("socat timed out; output=%s", out)
	}
	return string(out), runErr
}

func TestIPRecvErrUDPConnectICMP(t *testing.T) {
	text, runErr := runRecvErrClosedPort(t, "UDP4:127.0.0.1:%d,ip-recverr")
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrZeroOmitsDiagnostics(t *testing.T) {
	text, runErr := runRecvErrClosedPort(t, "UDP4:127.0.0.1:%d,ip-recverr=0")
	if runErr == nil {
		t.Fatalf("expected connection refused exit; output=%s", text)
	}
	if recverrOutputHasDiagnostic(text) {
		t.Fatalf("ip-recverr=0 must not log ICMP/IP_RECVERR diagnostics: %s", text)
	}
	if !strings.Contains(strings.ToLower(text), "connection refused") {
		t.Fatalf("expected ordinary connection refused; output=%s", text)
	}
}

func TestIPRecvErrUDPSendtoICMP(t *testing.T) {
	text, runErr := runRecvErrClosedPort(t, "UDP4-SENDTO:127.0.0.1:%d,ip-recverr")
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrUDPDatagramICMP(t *testing.T) {
	text, runErr := runRecvErrClosedPort(t, "UDP4-DATAGRAM:127.0.0.1:%d,ip-recverr")
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}
