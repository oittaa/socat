//go:build e2e && linux

package e2e_test

import (
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

func closedUDP4Port(t *testing.T) int {
	t.Helper()
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()
	return port
}

// runRecvErrHeldStdin writes one datagram then keeps stdin open until ready
// reports true or socat exits. Exhausting stdin lets EOF/shutdown win the
// race against ICMP on slow hosts.
func runRecvErrHeldStdin(t *testing.T, addressFmt string, ready func(string) bool) (string, error) {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	cmd := exec.Command(socatBin(t), "-d", "-d", "-d", "-t", "1",
		"STDIO",
		fmt.Sprintf(addressFmt, closedUDP4Port(t)))
	cmd.Stdin = stdinR
	cmd.Stdout = io.Discard
	proc, err := startTestProcess(cmd)
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdinW.Close()
		proc.stop()
	})
	if _, err := io.WriteString(stdinW, "hi\n"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		text := proc.stderr.String()
		if ready != nil && ready(text) {
			break
		}
		select {
		case <-proc.done:
			waitErr, _ := proc.status()
			return proc.stderr.String(), waitErr
		case <-time.After(20 * time.Millisecond):
		}
	}
	_ = stdinW.Close()
	select {
	case <-proc.done:
	case <-time.After(3 * time.Second):
		proc.stop()
		t.Fatalf("socat did not exit; output=%s", proc.stderr.String())
	}
	waitErr, _ := proc.status()
	return proc.stderr.String(), waitErr
}

func TestIPRecvErrUDPConnectICMP(t *testing.T) {
	text, runErr := runRecvErrHeldStdin(t, "UDP4:127.0.0.1:%d,ip-recverr", recverrOutputHasDiagnostic)
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrZeroOmitsDiagnostics(t *testing.T) {
	text, runErr := runRecvErrHeldStdin(t, "UDP4:127.0.0.1:%d,ip-recverr=0", func(text string) bool {
		return strings.Contains(strings.ToLower(text), "connection refused")
	})
	if recverrOutputHasDiagnostic(text) {
		t.Fatalf("ip-recverr=0 must not log ICMP/IP_RECVERR diagnostics: %s", text)
	}
	if !strings.Contains(strings.ToLower(text), "connection refused") {
		t.Fatalf("expected ordinary connection refused (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrUDPSendtoICMP(t *testing.T) {
	text, runErr := runRecvErrHeldStdin(t, "UDP4-SENDTO:127.0.0.1:%d,ip-recverr", recverrOutputHasDiagnostic)
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrUDPDatagramICMP(t *testing.T) {
	text, runErr := runRecvErrHeldStdin(t, "UDP4-DATAGRAM:127.0.0.1:%d,ip-recverr", recverrOutputHasDiagnostic)
	if !recverrOutputHasDiagnostic(text) {
		t.Fatalf("missing recverr/ICMP diagnostics (err=%v): %s", runErr, text)
	}
}

func TestIPRecvErrEndCloseDeliversDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		addressFmt string
	}{
		{name: "connect", addressFmt: "UDP4:127.0.0.1:%d,ip-recverr,end-close"},
		{name: "sendto", addressFmt: "UDP4-SENDTO:127.0.0.1:%d,ip-recverr,end-close"},
		{name: "datagram", addressFmt: "UDP4-DATAGRAM:127.0.0.1:%d,ip-recverr,end-close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, runErr := runRecvErrHeldStdin(t, tc.addressFmt, recverrOutputHasDiagnostic)
			if !recverrOutputHasDiagnostic(text) {
				t.Fatalf("end-close swallowed recverr/ICMP diagnostics (err=%v): %s", runErr, text)
			}
		})
	}
}
