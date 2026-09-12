//go:build e2e

package e2e_test

import (
	"bytes"
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
			if checkErr := rejectedOptionResult(out, err, tc.want); checkErr != nil {
				t.Fatal(checkErr)
			}
		})
	}

	t.Run("handshake-timeout-on-tls", func(t *testing.T) {
		port := stallTCPPeer(t)
		out, err := runWithTimeout(t, 2*time.Second, bin, "-u",
			fmt.Sprintf("TLS:127.0.0.1:%d,verify=0,handshake-timeout=0.2", port), "PIPE")
		if checkErr := acceptedOptionResult(out, err, handshakeProgress); checkErr != nil {
			t.Fatal(checkErr)
		}
	})
	t.Run("handshake-timeout-on-ws", func(t *testing.T) {
		port := stallTCPPeer(t)
		out, err := runWithTimeout(t, 2*time.Second, bin, "-u",
			fmt.Sprintf("WS:127.0.0.1:%d,handshake-timeout=0.2", port), "PIPE")
		if checkErr := acceptedOptionResult(out, err, handshakeProgress); checkErr != nil {
			t.Fatal(checkErr)
		}
	})
	t.Run("handshake-timeout-on-dtls", func(t *testing.T) {
		port := silentUDPPeer(t)
		out, err := runWithTimeout(t, 2*time.Second, bin, "-u",
			fmt.Sprintf("DTLS:127.0.0.1:%d,verify=0,handshake-timeout=0.2", port), "PIPE")
		if checkErr := acceptedOptionResult(out, err, handshakeProgress); checkErr != nil {
			t.Fatal(checkErr)
		}
	})
	t.Run("handshake-timeout-on-quic", func(t *testing.T) {
		port := silentUDPPeer(t)
		out, err := runWithTimeout(t, 2*time.Second, bin, "-u",
			fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,handshake-timeout=0.2", port), "PIPE")
		if checkErr := acceptedOptionResult(out, err, handshakeProgress); checkErr != nil {
			t.Fatal(checkErr)
		}
	})

	t.Run("append-on-tcp-accepted", func(t *testing.T) {
		port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
		})
		payload := []byte("append-ok\n")
		out, err := runWithTimeoutInput(t, 3*time.Second, payload, bin, "stdin!!stdout",
			fmt.Sprintf("TCP4:127.0.0.1:%d,append", port))
		if checkErr := acceptedConnectedResult(out, err, payload, srv.stderr.String()); checkErr != nil {
			t.Fatal(checkErr)
		}
	})
	t.Run("readbytes-on-tcp-accepted", func(t *testing.T) {
		port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(bin, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port), "PIPE")
		})
		out, err := runWithTimeoutInput(t, 3*time.Second, []byte("hello"), bin, "stdin!!stdout",
			fmt.Sprintf("TCP4:127.0.0.1:%d,readbytes=4", port))
		if checkErr := acceptedConnectedResult(out, err, []byte("hell"), srv.stderr.String()); checkErr != nil {
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

func TestForcedFamilyBindE2E(t *testing.T) {
	bin := socatBin(t)
	out, err := runWithTimeout(t, 2*time.Second, bin, "TCP4-LISTEN:0,bind=::,reuseaddr,fork", "PIPE")
	if checkErr := invalidFamilyBindResult(out, err); checkErr != nil {
		t.Fatal(checkErr)
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
		if checkErr := invalidFamilyBindResult(clOut, clErr); checkErr != nil {
			t.Fatal(checkErr)
		}
	}
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
