package proxyopen

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestIgnoreCRZeroDoesNotRejectHTTP2(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=1,ignorecr=0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected dial/handshake failure, not success")
	}
	if strings.Contains(err.Error(), "ignorecr") {
		t.Fatalf("ignorecr=0 must not affect HTTP/2: %v", err)
	}
}

func TestReadProxyResponseLineCountsCRWhenIgnoreCR(t *testing.T) {
	data := "HTTP/1.0 200 OK\r\n"
	total := 0
	line, err := readProxyResponseLine(bufio.NewReader(strings.NewReader(data)), &total, true)
	if err != nil {
		t.Fatal(err)
	}
	if line != "HTTP/1.0 200 OK\n" {
		t.Fatalf("line=%q", line)
	}
	if total != len(data) {
		t.Fatalf("total=%d want %d (CRs still count toward the size cap)", total, len(data))
	}
}

func TestProxyHTTP1BlankLine(t *testing.T) {
	if !proxyHTTP1BlankLine("\r\n") || !proxyHTTP1BlankLine("\n") {
		t.Fatal("expected blank CRLF and LF")
	}
	if proxyHTTP1BlankLine("\r\r\n") || proxyHTTP1BlankLine("X\r\n") {
		t.Fatal("non-blank lines must not match without ignorecr stripping")
	}
}
