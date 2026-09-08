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
