//go:build e2e

package e2e_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestOptionCapabilityRestrictions(t *testing.T) {
	bin := socatBin(t)
	rejected := []struct {
		name string
		left string
		want string
	}{
		{name: "pty-on-tcp", left: "TCP:127.0.0.1:1,pty", want: "not supported"},
		{name: "echo-on-tcp", left: "TCP:127.0.0.1:1,echo", want: "not supported"},
		{name: "fork-on-udp", left: "UDP:127.0.0.1:1,fork", want: "not supported"},
		{name: "excl-on-create", left: "CREATE:file,excl", want: "not supported"},
		{name: "o-direct-on-create", left: "CREATE:file,o-direct", want: "not supported"},
		{name: "o-sync-on-create", left: "CREATE:file,o-sync", want: "not supported"},
		{name: "accept-timeout-on-recvfrom", left: "UDP-RECVFROM:1,accept-timeout=0.1", want: "not supported"},
		{name: "handshake-timeout-on-tcp", left: "TCP:host:port,handshake-timeout=1", want: "not supported"},
		{name: "handshake-timeout-on-open", left: "OPEN:file,handshake-timeout=1", want: "not supported"},
		{name: "handshake-timeout-on-exec", left: "EXEC:true,handshake-timeout=1", want: "not supported"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runWithTimeout(t, 2*time.Second, bin, "-u", tc.left, "PIPE")
			requireCleanFailure(t, out, err)
			if !bytes.Contains(out, []byte(tc.want)) {
				t.Fatalf("output=%q want substring %q", out, tc.want)
			}
		})
	}

	t.Run("readbytes-on-tcp-accepted", func(t *testing.T) {
		out, err, stderr := runTCPAcceptedOption(t, "readbytes=4", []byte("hello"))
		if checkErr := acceptedConnectedResult(out, err, []byte("hell"), stderr); checkErr != nil {
			t.Fatal(checkErr)
		}
	})

	if classic := os.Getenv("SOCAT_CLASSIC"); classic != "" {
		t.Run("classic-differential", func(t *testing.T) {
			for _, spec := range []string{
				"TCP:127.0.0.1:1,pty",
				"TCP:127.0.0.1:1,echo",
				"UDP:127.0.0.1:1,fork",
				"CREATE:" + t.TempDir() + "/f,excl",
				"CREATE:" + t.TempDir() + "/g,o-direct",
			} {
				goOut, goErr := runWithTimeout(t, 2*time.Second, bin, "-u", spec, "PIPE")
				if harnessTimedOut(goErr) {
					t.Errorf("%s: go timed out: %s", spec, goOut)
					continue
				}
				clOut, clErr := runWithTimeout(t, 2*time.Second, classic, "-u", spec, "PIPE")
				if harnessTimedOut(clErr) {
					t.Errorf("%s: classic timed out: %s", spec, clOut)
					continue
				}
				goReject := bytes.Contains(goOut, []byte("not supported"))
				clReject := bytes.Contains(clOut, []byte("not supported"))
				if goReject != clReject {
					t.Errorf("%s: go reject=%v classic reject=%v\ngo: %s\nclassic: %s", spec, goReject, clReject, goOut, clOut)
				}
			}
		})
	}
}

func TestClientHandshakeTimeoutStalledPeer(t *testing.T) {
	bin := socatBin(t)
	const handshake = 200 * time.Millisecond
	harness := 3 * time.Second
	minElapsed := handshake - 50*time.Millisecond
	maxElapsed := 10 * handshake
	tests := []struct {
		name string
		udp  bool
		spec string
	}{
		{name: "tls", spec: "TLS:127.0.0.1:%d,verify=0,handshake-timeout=0.2"},
		{name: "ws", spec: "WS:127.0.0.1:%d,handshake-timeout=0.2"},
		{name: "dtls", udp: true, spec: "DTLS:127.0.0.1:%d,verify=0,handshake-timeout=0.2"},
		{name: "quic", udp: true, spec: "QUIC:127.0.0.1:%d,verify=0,handshake-timeout=0.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var port int
			if tc.udp {
				port = silentUDPPeer(t)
			} else {
				port = stallTCPPeer(t)
			}
			started := time.Now()
			out, err := runWithTimeout(t, harness, bin, "-u", fmt.Sprintf(tc.spec, port), "PIPE")
			elapsed := time.Since(started)
			if harnessTimedOut(err) {
				t.Fatalf("harness deadline killed socat after %s: %s", elapsed, out)
			}
			if outputShowsCrash(out) {
				t.Fatalf("abnormal termination after %s: %v: %s", elapsed, err, out)
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 1 {
				t.Fatalf("exit=%v want 1 after %s: %s", err, elapsed, out)
			}
			if bytes.Contains(out, []byte("not supported")) {
				t.Fatalf("handshake-timeout rejected: %s", out)
			}
			if elapsed < minElapsed {
				t.Fatalf("failed too quickly (%s): %s", elapsed, out)
			}
			if elapsed > maxElapsed {
				t.Fatalf("handshake timeout took %s (want <= %s): %s", elapsed, maxElapsed, out)
			}
		})
	}
}

func TestForcedFamilyBindE2E(t *testing.T) {
	bin := socatBin(t)
	out, err := runWithTimeout(t, 2*time.Second, bin, "TCP4-LISTEN:0,bind=::,reuseaddr,fork", "PIPE")
	requireCleanFailure(t, out, err)
	if !bytes.Contains(out, []byte("address family mismatch")) {
		t.Fatalf("want address family mismatch, got %s", out)
	}

	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,bind=127.0.0.1,reuseaddr", port), "PIPE")
	})
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("valid IPv4 bind did not accept: %v stderr=%s", err, srv.stderr.String())
	}
	_ = conn.Close()

	if classic := os.Getenv("SOCAT_CLASSIC"); classic != "" {
		clOut, clErr := runWithTimeout(t, 2*time.Second, classic, "TCP4-LISTEN:0,bind=::,reuseaddr,fork", "PIPE")
		requireCleanFailure(t, clOut, clErr)
		if !bytes.Contains(clOut, []byte("address family")) {
			t.Fatalf("classic want address family error, got %s", clOut)
		}
	}
}

func runTCPAcceptedOption(t *testing.T, option string, stdin []byte) ([]byte, error, string) {
	t.Helper()
	bin := socatBin(t)
	port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
	})
	out, err := runWithTimeoutInput(t, 3*time.Second, stdin, bin, "stdin!!stdout",
		fmt.Sprintf("TCP4:127.0.0.1:%d,%s", port, option))
	return out, err, srv.stderr.String()
}

func stallTCPPeer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 1)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func silentUDPPeer(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func requireCleanFailure(t *testing.T, out []byte, err error) {
	t.Helper()
	if harnessTimedOut(err) {
		t.Fatalf("harness deadline killed the process: %v: %s", err, out)
	}
	if outputShowsCrash(out) {
		t.Fatalf("abnormal termination: %v: %s", err, out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("exit=%v want 1: %s", err, out)
	}
}

func acceptedConnectedResult(out []byte, err error, want []byte, srvStderr string) error {
	if harnessTimedOut(err) {
		return fmt.Errorf("accepted option timed out: %w: %s srv=%s", err, out, srvStderr)
	}
	if bytes.Contains(out, []byte("not supported")) {
		return fmt.Errorf("unexpected option rejection: %s srv=%s", out, srvStderr)
	}
	if err != nil {
		return fmt.Errorf("accepted option failed: %v: %s srv=%s", err, out, srvStderr)
	}
	if !bytes.Equal(out, want) {
		return fmt.Errorf("payload=%q want %q srv=%s", out, want, srvStderr)
	}
	return nil
}
