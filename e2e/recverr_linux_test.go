//go:build e2e && linux

package e2e_test

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIPRecvErrUDPConnectICMP(t *testing.T) {
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()

	cmd := exec.Command(socatBin(t), "-d", "-d", "-d", "-t", "1",
		"STDIO",
		"UDP4:127.0.0.1:"+strconv.Itoa(port)+",ip-recverr")
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
	if runErr == nil {
		t.Fatalf("expected connection refused exit; output=%s", out)
	}
	text := string(out)
	if !strings.Contains(strings.ToLower(text), "connection refused") &&
		!strings.Contains(text, "IP_RECVERR") &&
		!strings.Contains(text, "received ICMP") {
		t.Fatalf("missing recverr/ICMP diagnostics: %s", text)
	}
}
