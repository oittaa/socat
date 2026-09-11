package proxyopen

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func assertPlaintextHiddenTLSRejected(t *testing.T, err error, spelling string) {
	t.Helper()
	if err == nil {
		t.Fatal("hidden TLS option opened a plaintext transport")
	}
	msg := err.Error()
	quoted := `"` + spelling + `"`
	if !strings.Contains(msg, quoted) {
		t.Fatalf("missing %s: %v", quoted, err)
	}
	if strings.Contains(msg, "not supported (") {
		t.Fatalf("TLS reject on plaintext: %v", err)
	}
}

func TestSOCKS5ConnectRejectsFIPS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockSOCKS5Echo(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80,fips=1,socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openSOCKS5Connect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "fips")
}

func TestSOCKS4ConnectRejectsMethodSpelling(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockSOCKS4Echo(t, ln, false)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("SOCKS4:127.0.0.1:127.0.0.1:80,method=TLS1,socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openSOCKS4Connect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "method")
}

func TestPROXYHTTP1RejectsFIPS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,fips=1,proxyport=" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "fips")
}

func TestH2cCONNECTRejectsFIPS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	var p http.Protocols
	p.SetHTTP1(false)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: connectEchoHandler(), Protocols: &p}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,fips=1,proxyport=" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "fips")
}

func TestH2CONNECTRejectsEnabledFIPS(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=1,verify=0,fips=1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), `"fips"`) || !strings.Contains(err.Error(), "OpenSSL FIPS module") {
		t.Fatalf("%v", err)
	}
}

func TestH2CONNECTDisabledFIPSStillEchoes(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0,fips=0", port))
}
