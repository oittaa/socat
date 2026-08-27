package proxyopen

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestProxyHTTP1IgnoreCR(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		chunks   []string
		wantErr  string
		wantBody string
	}{
		{
			name:   "ignorecr-lf-only-200",
			spec:   "PROXY:proxy.example:target.example:443,ignorecr",
			chunks: []string{"HTTP/1.0 200 OK\n\n"},
		},
		{
			name:   "ignorecr-equals-1-lf-only-200",
			spec:   "PROXY:proxy.example:target.example:443,ignorecr=1",
			chunks: []string{"HTTP/1.0 200 Connection established\nX-A: 1\n\n"},
		},
		{
			name:    "ignorecr-off-lf-only-fails",
			spec:    "PROXY:proxy.example:target.example:443",
			chunks:  []string{"HTTP/1.0 200 OK\n\n"},
			wantErr: "not CRLF-terminated",
		},
		{
			name:    "ignorecr-zero-after-flag-lf-only-fails",
			spec:    "PROXY:proxy.example:target.example:443,ignorecr,ignorecr=0",
			chunks:  []string{"HTTP/1.0 200 OK\n\n"},
			wantErr: "not CRLF-terminated",
		},
		{
			name:   "last-wins-zero-then-flag-allows-lf",
			spec:   "PROXY:proxy.example:target.example:443,ignorecr=0,ignorecr",
			chunks: []string{"HTTP/1.0 200 OK\n\n"},
		},
		{
			name:   "crlf-without-ignorecr",
			spec:   "PROXY:proxy.example:target.example:443",
			chunks: []string{"HTTP/1.0 200 OK\r\n\r\n"},
		},
		{
			name:   "crlf-with-ignorecr",
			spec:   "PROXY:proxy.example:target.example:443,ignorecr",
			chunks: []string{"HTTP/1.1 200 OK\r\n\r\n"},
		},
		{
			name:     "mixed-line-endings-with-ignorecr",
			spec:     "PROXY:proxy.example:target.example:443,ignorecr",
			chunks:   []string{"HTTP/1.0 200 OK\r\nX-A: 1\nX-B: 2\r\n\nTUNNEL"},
			wantBody: "TUNNEL",
		},
		{
			name:    "mixed-line-endings-without-ignorecr",
			spec:    "PROXY:proxy.example:target.example:443",
			chunks:  []string{"HTTP/1.0 200 OK\r\nX-A: 1\n\n"},
			wantErr: "not CRLF-terminated",
		},
		{
			name:     "fragmented-cr-then-lf-without-ignorecr",
			spec:     "PROXY:proxy.example:target.example:443",
			chunks:   []string{"HTTP/1.0 200 OK\r", "\nX-A: 1\r", "\n\r\nBODY"},
			wantBody: "BODY",
		},
		{
			name:     "fragmented-cr-then-lf-with-ignorecr",
			spec:     "PROXY:proxy.example:target.example:443,ignorecr",
			chunks:   []string{"HTTP/1.0 200 OK\r", "\nX-A: 1\r", "\n\r\nBODY"},
			wantBody: "BODY",
		},
		{
			name:     "ignorecr-extra-cr-before-final-lf",
			spec:     "PROXY:proxy.example:target.example:443,ignorecr",
			chunks:   []string{"HTTP/1.0 200 OK\r\n\r\r\nKEEP"},
			wantBody: "KEEP",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotReq, body, err := handshakeProxyResponse(t, tc.spec, tc.chunks)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(gotReq, "CONNECT 192.0.2.1:443 HTTP/1.0\r\n") {
				t.Fatalf("CONNECT request missing CRLF request line: %q", gotReq)
			}
			if !strings.Contains(gotReq, "\r\n\r\n") {
				t.Fatalf("CONNECT request headers are not CRLF-terminated: %q", gotReq)
			}
			if tc.wantBody != "" && body != tc.wantBody {
				t.Fatalf("leftover body=%q want %q", body, tc.wantBody)
			}
		})
	}
}

func handshakeProxyResponse(t *testing.T, spec string, chunks []string) (req string, body string, err error) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	type serverResult struct {
		req string
		err error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(server)
		var b strings.Builder
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				srvCh <- serverResult{req: b.String(), err: rerr}
				return
			}
			b.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		for i, chunk := range chunks {
			if i > 0 {
				time.Sleep(20 * time.Millisecond)
			}
			if _, werr := io.WriteString(server, chunk); werr != nil {
				srvCh <- serverResult{req: b.String(), err: werr}
				return
			}
		}
		srvCh <- serverResult{req: b.String()}
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	c, herr := proxyHTTP1Handshake(client, s, "192.0.2.1", "443", "1.0")
	select {
	case got := <-srvCh:
		if got.err != nil && herr == nil {
			t.Fatalf("server: %v", got.err)
		}
		req = got.req
	case <-time.After(2 * time.Second):
		t.Fatal("server goroutine did not finish")
	}
	if herr != nil {
		return req, "", herr
	}
	_ = c.SetDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if rerr != nil && rerr != io.EOF && !isTimeoutErr(rerr) {
		return req, "", rerr
	}
	return req, string(buf[:n]), nil
}

func isTimeoutErr(err error) bool {
	nerr, ok := err.(net.Error)
	return ok && nerr.Timeout()
}

func TestIgnoreCRRejectedOnHTTP2AndHTTP3(t *testing.T) {
	for _, spec := range []string{
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2,ignorecr",
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2.0,ignorecr=1",
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,ignorecr",
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,ignorecr",
	} {
		t.Run(spec, func(t *testing.T) {
			s, err := parse.ParseSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
			if err == nil || !strings.Contains(err.Error(), "HTTP/1") {
				t.Fatalf("error=%v want ignorecr HTTP/1-only rejection", err)
			}
		})
	}
}

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

func TestReadProxyResponseLineFragmentedCRLF(t *testing.T) {
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	errCh := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(w, "HTTP/1.1 200 OK\r"); err != nil {
			errCh <- err
			return
		}
		time.Sleep(30 * time.Millisecond)
		_, err := io.WriteString(w, "\n")
		errCh <- err
	}()
	br := bufio.NewReaderSize(r, maxHTTP1ProxyResponseBytes+1)
	total := 0
	line, err := readProxyResponseLine(br, &total, false)
	if err != nil {
		t.Fatal(err)
	}
	if line != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("line=%q", line)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
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
