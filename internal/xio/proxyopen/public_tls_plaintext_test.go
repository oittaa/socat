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

func optionSpelling(opt string) string {
	name, _, _ := strings.Cut(opt, "=")
	return name
}

func TestPROXYHTTP1RejectsPublicTLSOptions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, opt := range []string{
		"cert=x", "key=x", "cafile=x", "capath=x", "verify=0",
		"commonname=h", "snihost=h", "nosni", "ciphers=ECDHE-RSA-AES128-GCM-SHA256",
		"compress=none", "openssl-min-proto-version=TLS1.2",
		"openssl-max-proto-version=TLS1.3", "alpn=h2",
	} {
		s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9," + opt + ",proxyport=" + strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		if o != nil {
			_ = o.Close()
		}
		assertPlaintextHiddenTLSRejected(t, err, optionSpelling(opt))
	}
}

func TestPROXYHTTP11RejectsVerify(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=1.1,verify=0,proxyport=" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "verify")
}

func TestPROXYHTTP1RejectsCertificateAlias(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockHTTP1CONNECTEcho(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,openssl-certificate=server.pem,proxyport=" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "openssl-certificate")
}

func TestPROXYHTTP1RejectsCertBeforeDNS(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:127.0.0.1:no-such-host.invalid:9,cert=x,proxyport=1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "cert")
}

func TestH2cCONNECTRejectsALPN(t *testing.T) {
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

	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,alpn=h2,proxyport=" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "alpn")
}

func TestH2CONNECTCompressNoneStillEchoes(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0,compress=none", port))
}
