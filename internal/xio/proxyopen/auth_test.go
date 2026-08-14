package proxyopen

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestProxyAuthFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth")
	if err := os.WriteFile(p, []byte("user:s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec("PROXY:127.0.0.1:h:80,proxy-authorization-file=" + p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proxyAuthHeader(s)
	if err != nil {
		t.Fatal(err)
	}
	want := "Proxy-authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user:s3cr3t\n")) + "\r\n"
	if h != want {
		t.Fatalf("got %q want %q", h, want)
	}
	if !strings.Contains(h, "dXNlcjpzM2NyM3QK") {
		t.Fatalf("classic test expects that b64 blob: %q", h)
	}
}
