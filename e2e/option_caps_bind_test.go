//go:build e2e

package e2e_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOptionCapabilityRestrictions(t *testing.T) {
	bin := socatBin(t)
	cases := []struct {
		name    string
		left    string
		wantErr string
	}{
		{name: "pty-on-tcp", left: "TCP:127.0.0.1:1,pty", wantErr: "not supported"},
		{name: "echo-on-tcp", left: "TCP:127.0.0.1:1,echo", wantErr: "not supported"},
		{name: "fork-on-udp", left: "UDP:127.0.0.1:1,fork", wantErr: "not supported"},
		{name: "excl-on-create", left: "CREATE:file,excl", wantErr: "not supported"},
		{name: "o-direct-on-create", left: "CREATE:file,o-direct", wantErr: "not supported"},
		{name: "accept-timeout-on-recvfrom", left: "UDP-RECVFROM:1,accept-timeout=0.1", wantErr: "not supported"},
		{name: "handshake-timeout-on-tcp", left: "TCP:host:port,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-open", left: "OPEN:file,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-exec", left: "EXEC:true,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-tls", left: "TLS:127.0.0.1:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-quic", left: "QUIC:127.0.0.1:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-ws", left: "WS:127.0.0.1:1,handshake-timeout=1"},
		{name: "append-on-tcp-accepted", left: "TCP:127.0.0.1:1,append"},
		{name: "readbytes-on-tcp-accepted", left: "TCP:127.0.0.1:1,readbytes=4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctxWait := 2 * time.Second
			if tc.wantErr == "" {
				ctxWait = 500 * time.Millisecond
			}
			cmd := exec.Command(bin, "-u", tc.left, "PIPE")
			out, err := runWithTimeout(t, cmd, ctxWait)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got success: %s", tc.wantErr, out)
				}
				if !strings.Contains(string(out), tc.wantErr) {
					t.Fatalf("output=%q want substring %q", out, tc.wantErr)
				}
				return
			}
			if strings.Contains(string(out), "not supported") {
				t.Fatalf("unexpected option rejection: %s", out)
			}
		})
	}

	if classic := os.Getenv("SOCAT_CLASSIC"); classic != "" {
		t.Run("classic-differential", func(t *testing.T) {
			for _, spec := range []string{
				"TCP:127.0.0.1:1,pty",
				"TCP:127.0.0.1:1,echo",
				"UDP:127.0.0.1:1,fork",
				"CREATE:" + t.TempDir() + "/f,excl",
				"CREATE:" + t.TempDir() + "/g,o-direct",
			} {
				goOut, _ := runWithTimeout(t, exec.Command(bin, "-u", spec, "PIPE"), 2*time.Second)
				clOut, _ := runWithTimeout(t, exec.Command(classic, "-u", spec, "PIPE"), 2*time.Second)
				goReject := strings.Contains(string(goOut), "not supported")
				clReject := strings.Contains(string(clOut), "not supported")
				if goReject != clReject {
					t.Errorf("%s: go reject=%v classic reject=%v\ngo: %s\nclassic: %s", spec, goReject, clReject, goOut, clOut)
				}
			}
		})
	}
}

func TestForcedFamilyBindE2E(t *testing.T) {
	bin := socatBin(t)
	out, err := runWithTimeout(t, exec.Command(bin, "TCP4-LISTEN:0,bind=::,reuseaddr,fork", "PIPE"), 2*time.Second)
	if err == nil {
		t.Fatalf("TCP4-LISTEN bind=:: succeeded: %s", out)
	}
	if !strings.Contains(string(out), "address family") && !strings.Contains(string(out), "bind") {
		t.Fatalf("want family/bind error, got %s", out)
	}

	ok := exec.Command(bin, "-u", "/dev/null", "TCP4-LISTEN:0,bind=127.0.0.1,reuseaddr,accept-timeout=0.05")
	out, err = runWithTimeout(t, ok, 3*time.Second)
	if err != nil && !strings.Contains(string(out), "accept timeout") && !strings.Contains(strings.ToLower(string(out)), "timeout") {
		// accept-timeout exits 0 in classic; our wrapper may still report it.
		if strings.Contains(string(out), "address family") {
			t.Fatalf("valid IPv4 bind failed: %s", out)
		}
	}

	if classic := os.Getenv("SOCAT_CLASSIC"); classic != "" {
		clOut, clErr := runWithTimeout(t, exec.Command(classic, "TCP4-LISTEN:0,bind=::,reuseaddr,fork", "PIPE"), 2*time.Second)
		if clErr == nil {
			t.Fatalf("classic accepted TCP4-LISTEN bind=:: : %s", clOut)
		}
	}
}

func runWithTimeout(t *testing.T, cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	t.Helper()
	timer := time.AfterFunc(d, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	return cmd.CombinedOutput()
}
