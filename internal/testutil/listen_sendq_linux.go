//go:build linux

package testutil

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TCPListenSendQ returns the kernel listen backlog (ss Send-Q) for a TCP
// listening socket. Listening sockets report the configured backlog in Send-Q.
func TCPListenSendQ(t testing.TB, addr net.Addr) int {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T, want *net.TCPAddr", addr)
	}
	ss, err := exec.LookPath("ss")
	if err != nil {
		t.Skip("ss not found")
	}
	port := strconv.Itoa(tcp.Port)
	out, err := exec.Command(ss, "-ltnH", "sport", "=", ":"+port).Output() // #nosec G204 -- argv is ss plus a decimal port from this test's listener; no shell
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	return parseSSSendQ(t, string(out), port)
}

func parseSSSendQ(t testing.TB, out, port string) int {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !strings.Contains(fields[3], ":"+port) && !strings.HasSuffix(fields[3], ":"+port) {
			continue
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("ss Send-Q %q: %v", fields[2], err)
		}
		return n
	}
	t.Fatalf("ss did not report a listening socket on port %s; output %q", port, out)
	return 0
}
