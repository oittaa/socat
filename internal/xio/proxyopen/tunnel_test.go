package proxyopen

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeNotify struct {
	io.ReadCloser
	closed chan struct{}
}

func (c *closeNotify) Close() error {
	err := c.ReadCloser.Close()
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return err
}

func TestOpenCONNECTTunnelSuccessLeavesContextLive(t *testing.T) {
	ctx, stop, cancel := proxyHandshakeContext(context.Background(), time.Hour)
	defer cancel()
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodConnect || req.Host != "example:443" || req.ContentLength != -1 {
				t.Fatalf("CONNECT request: method=%s host=%s cl=%d", req.Method, req.Host, req.ContentLength)
			}
			if req.Header.Get("Proxy-Authorization") != "" {
				t.Fatal("unexpected Proxy-Authorization")
			}
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		handshake: ctx,
		stopTimer: stop,
		url:       "https://proxy/",
		authority: "example:443",
		network:   "h2",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if ctx.Err() != nil {
		t.Fatalf("success cancelled handshake context: %v", ctx.Err())
	}
}

func TestOpenCONNECTTunnelSetsProxyAuthorization(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	var got string
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			got = req.Header.Get("Proxy-Authorization")
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		handshake: context.Background(),
		proxy:     addrconfig.Proxy{Authorization: addrconfig.OptionalString{Set: true, Value: "u:p"}},
		url:       "https://proxy/",
		authority: "t:1",
		network:   "h3",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got != want {
		t.Fatalf("auth=%q want %q", got, want)
	}
}

func TestOpenCONNECTTunnelRejectsNon2xxAndClosesBody(t *testing.T) {
	closed := make(chan struct{})
	body := &closeNotify{ReadCloser: io.NopCloser(strings.NewReader("no")), closed: closed}
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: body}, nil
		}),
		handshake: context.Background(),
		url:       "https://proxy/",
		authority: "t:1",
		network:   "h2",
	})
	if conn != nil || err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("response body not closed")
	}
}

func TestOpenCONNECTTunnelRoundTripErrorClosesPipe(t *testing.T) {
	var body io.Reader
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body = req.Body
			return nil, io.ErrUnexpectedEOF
		}),
		handshake: context.Background(),
		url:       "https://proxy/",
		authority: "t:1",
		network:   "h2",
	})
	if conn != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	n, rerr := body.Read(make([]byte, 1))
	if n != 0 || rerr != io.EOF {
		t.Fatalf("pipe after fail: n=%d err=%v want EOF", n, rerr)
	}
}

func TestOpenCONNECTTunnelTimeoutDoesNotReturnLiveTunnel(t *testing.T) {
	ctx, stop, cancel := proxyHandshakeContext(context.Background(), time.Hour)
	defer cancel()
	cancel()
	closed := make(chan struct{})
	body := &closeNotify{ReadCloser: io.NopCloser(strings.NewReader("")), closed: closed}
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		}),
		handshake: ctx,
		stopTimer: stop,
		url:       "https://proxy/",
		authority: "t:1",
		network:   "h2",
	})
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("response body not closed")
	}
}

func TestOpenCONNECTTunnelAuthConflictClosesPipe(t *testing.T) {
	called := false
	conn, err := openCONNECTTunnel(connectTunnel{
		roundTrip: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		handshake: context.Background(),
		proxy: addrconfig.Proxy{
			Authorization:     addrconfig.OptionalString{Set: true, Value: "inline"},
			AuthorizationFile: addrconfig.OptionalString{Set: true, Value: "file"},
		},
		url:       "https://proxy/",
		authority: "t:1",
		network:   "h2",
	})
	if conn != nil || err == nil || !strings.Contains(err.Error(), "proxy-authorization") {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	if called {
		t.Fatal("RoundTrip ran after auth conflict")
	}
}
