//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

// TestMLDSAEcho — TLS and QUIC mTLS echo with ML-DSA-44 certificates (Go 1.27
// crypto/mldsa, TLS 1.3 CertificateVerify). Classic socat has no ML-DSA.
func TestMLDSAEcho(t *testing.T) {
	bin := socatBin(t)
	certs := mustMLDSA44Trust(t)
	assertMLDSA44PEM(t, certs.CAFile)
	assertMLDSA44PEM(t, certs.ServerCert)
	assertMLDSA44PEM(t, certs.ClientCert)

	t.Run("TLS", func(t *testing.T) {
		port, srv := startTCPTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(bin, "-t", "2", fmt.Sprintf(
				"TLS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=1,min-version=TLS1.3,cert=%s,key=%s,cafile=%s",
				port, certs.ServerCert, certs.ServerKey, certs.CAFile,
			), "PIPE")
		})

		payload := fmt.Sprintf("mldsa-tls %d\n", time.Now().UnixNano())
		cli := exec.Command(bin, "-t", "2", "stdin!!stdout", fmt.Sprintf(
			"TLS:127.0.0.1:%d,verify=1,min-version=TLS1.3,cert=%s,key=%s,cafile=%s,commonname=localhost",
			port, certs.ClientCert, certs.ClientKey, certs.CAFile,
		))
		var cliErr bytes.Buffer
		cli.Stdin = bytes.NewBufferString(payload)
		cli.Stderr = &cliErr
		out, err := cli.Output()
		if err != nil {
			t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
		}
		if string(out) != payload {
			t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
		}
	})

	t.Run("QUIC", func(t *testing.T) {
		port, srv := startQUICTestServer(t, func(port int) *exec.Cmd {
			return exec.Command(bin, "-t", "2", fmt.Sprintf(
				"QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=1,cert=%s,key=%s,cafile=%s",
				port, certs.ServerCert, certs.ServerKey, certs.CAFile,
			), "PIPE")
		})

		payload := fmt.Sprintf("mldsa-quic %d\n", time.Now().UnixNano())
		cli := exec.Command(bin, "-t", "2", "stdin!!stdout", fmt.Sprintf(
			"QUIC:127.0.0.1:%d,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
			port, certs.ClientCert, certs.ClientKey, certs.CAFile,
		))
		var cliErr bytes.Buffer
		cli.Stdin = bytes.NewBufferString(payload)
		cli.Stderr = &cliErr
		out, err := cli.Output()
		if err != nil {
			t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
		}
		if string(out) != payload {
			t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
		}
	})
}

func mustMLDSA44Trust(t *testing.T) testcert.Bundle {
	t.Helper()
	bundle, err := testcert.WriteMLDSA44Trust(t.TempDir())
	if err != nil {
		if strings.Contains(err.Error(), "unavailable") {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	return bundle
}

func assertMLDSA44PEM(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no CERTIFICATE PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SignatureAlgorithm != x509.MLDSA44 {
		t.Fatalf("%s SignatureAlgorithm=%v want MLDSA44", path, cert.SignatureAlgorithm)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("%s public key %T, want *mldsa.PublicKey", path, cert.PublicKey)
	}
}
