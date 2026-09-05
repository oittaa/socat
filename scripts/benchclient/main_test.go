package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/dtls13"
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

func TestDialDTLSRoundTripAndProbe(t *testing.T) {
	dir := t.TempDir()
	if err := writeBenchCerts(dir); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := dtls13.Listen(pc, &dtls13.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()

	tlsCfg, err := clientTLS(filepath.Join(dir, "ca.pem"), "localhost", false, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	probe, err := runProbe("dtls", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	if probe.Version != "DTLS 1.3" {
		t.Fatalf("probe version=%q", probe.Version)
	}
	if probe.Cipher == "" || probe.Group == "" {
		t.Fatalf("probe cipher=%q group=%q", probe.Cipher, probe.Group)
	}

	c, closer, err := dial("dtls", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	payload := []byte("ping")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo=%q", got)
	}
}
