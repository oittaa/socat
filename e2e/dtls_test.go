//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDTLSAuthenticatedBinaryRelay(t *testing.T) {
	bin := socatBin(t)
	certs := writeE2ETrustCerts(t)
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	server, err := startTestProcess(exec.CommandContext(ctx, bin, "-T", "5",
		fmt.Sprintf("OPENSSL-DTLS-SERVER:%d,bind=127.0.0.1,fork,cert=%s,key=%s,cafile=%s,commonname=client,alpn=socat", port, certs.serverCert, certs.serverKey, certs.caFile), "PIPE"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()
	// DTLS retransmission covers a ClientHello sent before the server binds.
	payload := bytes.Repeat([]byte("authenticated DTLS\n"), 1000)
	client := exec.CommandContext(ctx, bin, "-t", "1", "-T", "5", "STDIN!!STDOUT",
		fmt.Sprintf("DTLS-CLIENT:127.0.0.1:%d,cert=%s,key=%s,cafile=%s,alpn=socat,min-version=DTLS1.3", port, certs.clientCert, certs.clientKey, certs.caFile))
	client.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	client.Stderr = &stderr
	output, err := client.Output()
	if err != nil || !bytes.Equal(output, payload) {
		t.Fatalf("DTLS binary echo = %d/%d bytes, %v; client=%s; server=%s", len(output), len(payload), err, stderr.String(), server.stderr.String())
	}
}

func TestDTLSDefaultBlockFileTransfer(t *testing.T) {
	bin := socatBin(t)
	certs := writeE2ETrustCerts(t)
	for _, toServer := range []bool{true, false} {
		t.Run(map[bool]string{true: "to-server", false: "to-client"}[toServer], func(t *testing.T) {
			dir := t.TempDir()
			source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "dest")
			payload := make([]byte, 32791)
			for i := range payload {
				payload[i] = byte(i * 29)
			}
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			port := freeUDPPort(t)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			serverAddr := fmt.Sprintf("DTLS-LISTEN:%d,bind=127.0.0.1,cert=%s,key=%s,cafile=%s,commonname=client", port, certs.serverCert, certs.serverKey, certs.caFile)
			clientAddr := fmt.Sprintf("DTLS:127.0.0.1:%d,cert=%s,key=%s,cafile=%s", port, certs.clientCert, certs.clientKey, certs.caFile)
			serverArgs := []string{"-u", "-T", "5", serverAddr, "CREAT:" + dest}
			clientArgs := []string{"-u", "-T", "5", "OPEN:" + source, clientAddr}
			if !toServer {
				serverArgs = []string{"-U", "-T", "5", serverAddr, "OPEN:" + source}
				clientArgs = []string{"-u", "-T", "5", clientAddr, "CREAT:" + dest}
			}
			server, err := startTestProcess(exec.CommandContext(ctx, bin, serverArgs...))
			if err != nil {
				t.Fatal(err)
			}
			defer server.stop()
			clientOutput, clientErr := exec.CommandContext(ctx, bin, clientArgs...).CombinedOutput()
			select {
			case <-server.done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			serverErr, _ := server.status()
			got, readErr := os.ReadFile(dest)
			if clientErr != nil || serverErr != nil || readErr != nil || !bytes.Equal(got, payload) {
				t.Fatalf("file transfer: got %d/%d bytes; client=%v %s; server=%v %s; read=%v", len(got), len(payload), clientErr, clientOutput, serverErr, server.stderr.String(), readErr)
			}
		})
	}
}
