package tlsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
)

func holdAcceptedConn(t *testing.T, ln net.Listener) {
	t.Helper()
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
}

func TestTLSConnectHandshakeTimeoutStalledPeer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	holdAcceptedConn(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("TLS:127.0.0.1:%d,verify=0,handshake-timeout=0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openTLSConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("stalled TLS peer did not time out")
	}
	elapsed := time.Since(started)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("failed too quickly (%s); handshake-timeout may not have been applied: %v", elapsed, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handshake timeout took %s: %v", elapsed, err)
	}
}

func TestTLSConnectHandshakeTimeoutZeroWaitsForDelayedPeer(t *testing.T) {
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(100 * time.Millisecond)
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(srv, srv)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("TLS:127.0.0.1:%d,verify=0,handshake-timeout=0", port))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	o, err := openTLSConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatalf("handshake-timeout=0 should wait for a delayed TLS peer: %v", err)
	}
	defer func() { _ = o.Close() }()
	if elapsed := time.Since(started); elapsed < 70*time.Millisecond {
		t.Fatalf("handshake returned in %s; delayed peer was not waited for", elapsed)
	}
}
