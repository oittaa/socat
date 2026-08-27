//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func proxyConnectEcho() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		buf := make([]byte, 8192)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
}

func TestPROXYHelpHTTPVersion(t *testing.T) {
	hh := capabilityOutput(t, "-hh")
	if !bytes.Contains(hh, []byte(" http-version ")) {
		t.Fatalf("-hh missing http-version:\n%s", hh)
	}
	if !bytes.Contains(hh, []byte(" h2c ")) {
		t.Fatalf("-hh missing h2c:\n%s", hh)
	}
	if !bytes.Contains(hh, []byte(" ignorecr ")) {
		t.Fatalf("-hh missing ignorecr:\n%s", hh)
	}
	hhh := capabilityOutput(t, "-hhh")
	if !bytes.Contains(hhh, []byte(" ignorecr ")) {
		t.Fatalf("-hhh missing ignorecr:\n%s", hhh)
	}
}

func TestPROXYIgnoreCRLFOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	errCh := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				errCh <- rerr
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if _, werr := io.WriteString(c, "HTTP/1.0 200 Connection established\n\n"); werr != nil {
			errCh <- werr
			return
		}
		_, _ = io.Copy(c, c)
		errCh <- nil
	}()

	bin := socatBin(t)
	payload := fmt.Sprintf("ignorecr-lf %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "-T", "2", "stdin!!stdout",
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,proxyport=%d,ignorecr", port),
	)
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client with ignorecr: %v %s", err, cliErr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
	select {
	case serr := <-errCh:
		if serr != nil {
			t.Fatalf("mock proxy: %v", serr)
		}
	default:
	}
}

func TestPROXYWithoutIgnoreCRRejectsLFOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.0 200 Connection established\n\n")
	}()

	bin := socatBin(t)
	cli := exec.Command(bin, "-T", "2", "stdin!!stdout",
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,proxyport=%d", port),
	)
	cli.Stdin = bytes.NewBufferString("should-fail\n")
	out, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("LF-only response succeeded without ignorecr: %s", out)
	}
	if !bytes.Contains(out, []byte("CRLF-terminated")) && !bytes.Contains(out, []byte("ignorecr")) {
		t.Fatalf("error=%v output=%s want CRLF/ignorecr diagnostic", err, out)
	}
}

func TestPROXYH2Echo(t *testing.T) {
	bin := socatBin(t)
	srv := httptest.NewUnstartedServer(proxyConnectEcho())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	payload := fmt.Sprintf("h2-connect %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout",
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0", port),
	)
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v %s", err, cliErr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
}

func TestPROXYH3Echo(t *testing.T) {
	bin := socatBin(t)
	certs := writeE2ETrustCerts(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	srv := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{mustLoadTLS(t, certs.serverCert, certs.serverKey)},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		},
		Handler: proxyConnectEcho(),
	}
	go srv.Serve(pc)
	defer func() {
		_ = srv.Close()
		_ = pc.Close()
	}()

	payload := fmt.Sprintf("h3-connect %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "stdin!!stdout",
		fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%s,verify=0", port),
	)
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v %s", err, cliErr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
}

func mustLoadTLS(t *testing.T, cert, key string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
