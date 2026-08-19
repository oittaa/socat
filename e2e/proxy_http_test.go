//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
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
