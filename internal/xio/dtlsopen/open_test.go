package dtlsopen

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func spec(t *testing.T, value string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(value)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func credentials(t *testing.T) (server, client string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := testcert.NewAuthority("DTLS endpoint CA")
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := testcert.WriteCertPEM(caFile, ca.DER); err != nil {
		t.Fatal(err)
	}
	options := make([]string, 2)
	for i, name := range []string{"localhost", "client"} {
		usage := x509.ExtKeyUsageServerAuth
		if i == 1 {
			usage = x509.ExtKeyUsageClientAuth
		}
		leaf, err := ca.Leaf(name, []x509.ExtKeyUsage{usage}, nil, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		cert, key, err := leaf.WriteCertAndKey(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		options[i] = fmt.Sprintf(",cert=%s,key=%s,cafile=%s", cert, key, caFile)
	}
	return options[0], options[1] + ",commonname=localhost"
}

func TestDTLSHandshakeReceiveTimeout(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	for _, option := range []string{"so-rcvtimeo=0.05", "rcvtimeo=0.05,retry=1,interval=0"} {
		t.Run(option, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			o, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+peer.LocalAddr().String()+",verify=0,handshake-timeout=0,"+option), xio.ModeRDWR, nil)
			if o != nil {
				_ = o.Close()
			}
			if !errors.Is(err, dtls13.ErrHandshakeReadTimeout) {
				t.Fatalf("blackhole handshake = %v; want receive timeout", err)
			}
		})
	}
}
