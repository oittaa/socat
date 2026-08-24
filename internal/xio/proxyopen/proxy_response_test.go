package proxyopen

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestProxyHTTP1RejectsOversizedResponseLine(t *testing.T) {
	testOversizedProxyResponse(t, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("a", maxHTTP1ProxyResponseBytes)+"\r\n\r\n")
}

func TestProxyHTTP1RejectsOversizedResponseHeaders(t *testing.T) {
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 OK\r\n")
	for response.Len() <= maxHTTP1ProxyResponseBytes {
		response.WriteString("X-Padding: ")
		response.WriteString(strings.Repeat("b", 1000))
		response.WriteString("\r\n")
	}
	response.WriteString("\r\n")
	testOversizedProxyResponse(t, response.String())
}

func testOversizedProxyResponse(t *testing.T, response string) {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	done := make(chan error, 1)
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, err := server.Write([]byte(response))
		done <- err
	}()

	s, err := parse.ParseSpec("PROXY:proxy.example:target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct{ err error }
	resultCh := make(chan result, 1)
	go func() {
		_, err := proxyHTTP1Handshake(client, s, "192.0.2.1", "443", "1.0")
		resultCh <- result{err: err}
	}()
	select {
	case got := <-resultCh:
		if got.err == nil || !strings.Contains(got.err.Error(), "exceed") {
			t.Fatalf("proxyHTTP1Handshake error = %v, want size limit", got.err)
		}
	case <-ctx.Done():
		t.Fatal(fmt.Errorf("proxy handshake did not reject oversized response: %w", ctx.Err()))
	}
	_ = client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("proxy server goroutine did not exit")
	}
}

func TestProxyHTTP1ConnectTarget(t *testing.T) {
	tests := []struct {
		name        string
		connectHost string
		port        string
		want        string
	}{
		{name: "ipv4", connectHost: "192.0.2.1", port: "443", want: "CONNECT 192.0.2.1:443 HTTP/1.0\r\n"},
		{name: "ipv6", connectHost: "2001:db8::1", port: "443", want: "CONNECT [2001:db8::1]:443 HTTP/1.0\r\n"},
		{name: "hostname", connectHost: "example.com", port: "80", want: "CONNECT example.com:80 HTTP/1.0\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			gotCh := make(chan string, 1)
			go func() {
				br := bufio.NewReader(server)
				line, err := br.ReadString('\n')
				if err != nil {
					gotCh <- err.Error()
					return
				}
				gotCh <- line
				_, _ = br.ReadString('\n')
				_, _ = server.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
			}()
			s, err := parse.ParseSpec("PROXY:proxy.example:target.example:443")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proxyHTTP1Handshake(client, s, tc.connectHost, tc.port, "1.0"); err != nil {
				t.Fatal(err)
			}
			if got := <-gotCh; got != tc.want {
				t.Fatalf("request line=%q want %q", got, tc.want)
			}
		})
	}
}
