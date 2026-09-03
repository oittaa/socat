//go:build e2e && linux

package e2e_test

import (
	"fmt"
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

	cmd := exec.Command(socatBin(t), "-d", "-d", "-d", "-t", "1",
		"STDIO",
		fmt.Sprintf(addressFmt, port))
	cmd.Stdin = strings.NewReader("hi\n")
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
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
