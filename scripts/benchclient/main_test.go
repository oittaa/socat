package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePayloadMatchesBenchmarkStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := writePayload(path, 1024*1024); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(data)
	want, err := hex.DecodeString("925f959b52e80db3cfe583ac121e664503ffa806c9fc1626de8dd16fa54e2648")
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:]) != string(want) {
		t.Fatalf("payload hash=%x", got)
	}
}

func TestWriteBenchCerts(t *testing.T) {
	dir := t.TempDir()
	if err := writeBenchCerts(dir); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load benchmark CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
