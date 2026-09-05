//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func TestDTLSAuthenticatedBinaryRelay(t *testing.T) {
	bin := socatBin(t)
	certs := writeE2ETrustCerts(t)
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	server, err := startTestProcess(exec.CommandContext(ctx, bin, "-b", "1024", "-T", "5",
		fmt.Sprintf("OPENSSL-DTLS-SERVER:%d,bind=127.0.0.1,fork,cert=%s,key=%s,cafile=%s,commonname=client,alpn=socat", port, certs.serverCert, certs.serverKey, certs.caFile), "PIPE"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()
	// DTLS retransmission covers a ClientHello sent before the server binds.
	payload := bytes.Repeat([]byte("authenticated DTLS\n"), 40)
	client := exec.CommandContext(ctx, bin, "-b", "1024", "-t", "1", "-T", "5", "STDIN!!STDOUT",
		fmt.Sprintf("DTLS-CLIENT:127.0.0.1:%d,cert=%s,key=%s,cafile=%s,alpn=socat,min-version=DTLS1.3", port, certs.clientCert, certs.clientKey, certs.caFile))
	client.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	client.Stderr = &stderr
	output, err := client.Output()
	if err != nil || !bytes.Equal(output, payload) {
		t.Fatalf("DTLS binary echo = %q, %v; client=%s; server=%s", output, err, stderr.String(), server.stderr.String())
	}
}
