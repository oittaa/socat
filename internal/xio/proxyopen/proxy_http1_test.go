package proxyopen

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"syscall"
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

const http1ConnectEstablished = "HTTP/1.0 200 Connection established\r\n\r\n"

func mockHTTP1CONNECTEcho(t *testing.T, ln net.Listener) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	if !drainHTTP1CONNECTRequest(t, c) {
		return
	}
	if _, err := io.WriteString(c, http1ConnectEstablished); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

func drainHTTP1CONNECTRequest(t *testing.T, c net.Conn) bool {
	t.Helper()
	br := bufio.NewReader(c)
	sawConnect := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Errorf("CONNECT request: %v", err)
			return false
		}
		if !sawConnect {
			if len(line) < 8 || line[:8] != "CONNECT " {
				t.Errorf("want CONNECT, got %q", line)
				return false
			}
			sawConnect = true
		}
		if line == "\r\n" || line == "\n" {
			return true
		}
	}
}

func proxyHTTP1TCPHandshake(t *testing.T, payload string) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- accepted{err: err}
			return
		}
		if !drainHTTP1CONNECTRequest(t, c) {
			_ = c.Close()
			ch <- accepted{err: io.ErrUnexpectedEOF}
			return
		}
		if _, err := io.WriteString(c, http1ConnectEstablished+payload); err != nil {
			_ = c.Close()
			ch <- accepted{err: err}
			return
		}
		ch <- accepted{c: c}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := proxyHTTP1Handshake(client, addrconfig.Proxy{}, "192.0.2.1", 443, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatal(got.err)
	}
	t.Cleanup(func() { _ = got.c.Close() })
	return conn, got.c
}

func TestPROXYHTTP1CoalescedResponseDeliversPayload(t *testing.T) {
	const payload = "coalesced-app-data"
	conn, _ := proxyHTTP1TCPHandshake(t, payload)
	if _, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("buffered CONNECT must not implement syscall.Conn; relay poll or splice would skip the prefix")
	}
	if _, ok := conn.(interface{ NetConn() net.Conn }); !ok {
		t.Fatal("buffered CONNECT must expose NetConn for option lifecycle")
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("payload=%q err=%v", got, err)
	}
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
