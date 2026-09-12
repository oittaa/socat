package proxyopen

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

// TestPROXYHTTP1ConnectEcho covers the default PROXY address (HTTP/1.0 CONNECT).
// H2/H3 already have opener echo tests; HTTP/1 is what classic scripts use.
func TestPROXYHTTP1ConnectEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	echoViaPROXY(t, "PROXY:127.0.0.1:127.0.0.1:9,proxyport="+strconv.Itoa(port))
}

func TestPROXYHTTP11ConnectEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	echoViaPROXY(t, "PROXY:127.0.0.1:127.0.0.1:9,http-version=1.1,proxyport="+strconv.Itoa(port))
}

func mockHTTP1CONNECTEcho(t *testing.T, ln net.Listener) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	sawConnect := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Errorf("CONNECT request: %v", err)
			return
		}
		if !sawConnect {
			if len(line) < 8 || line[:8] != "CONNECT " {
				t.Errorf("want CONNECT, got %q", line)
				return
			}
			sawConnect = true
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if _, err := io.WriteString(c, "HTTP/1.0 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

func TestPROXYConnectTargetFromTypedLiteral(t *testing.T) {
	host, err := resolvePROXYConnectHost(t.Context(), addrconfig.Address{}, addrconfig.HostFromText("192.0.2.1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.0.2.1" {
		t.Fatalf("ipv4 host=%q", host)
	}
	if got := proxyCONNECTTarget(host, 443); got != "192.0.2.1:443" {
		t.Fatalf("ipv4 CONNECT=%q", got)
	}
	host, err = resolvePROXYConnectHost(t.Context(), addrconfig.Address{}, addrconfig.HostFromText("::1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "::1" {
		t.Fatalf("ipv6 host=%q", host)
	}
	if got := proxyCONNECTTarget(host, 443); got != "[::1]:443" {
		t.Fatalf("ipv6 CONNECT=%q", got)
	}
}
